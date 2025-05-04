#include "generated/block_protos.pb.h"
#include "generated/transaction_protos.pb.h"
#include "block.h"
#include "blake3.h"
#include "blockchain.h"
#include "crypto_utils.h"
#include "keccak.h"
#include "rocksdb/db.h"
#include "rollup/rollup_block.h"
#include "zk/winterfell_ffi.h"
#include "zk/winterfell_stark.h"
#include <cmath>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <json/json.h>
#include <sstream>
#include <thread>

namespace fs = std::filesystem;

const double BASE_BLOCK_REWARD = 10.0; // Fixed block reward per mined block
const double MAX_BURN_RATE = 0.05;     // Max 5% burn rate
const double MIN_BURN_RATE = 0.01;     // Min 1% burn rate

// ✅ Default Constructor (No Arguments)
Block::Block()
    : index(0), previousHash("0000"), minerAddress("System"), hash(""),
      difficulty(4) {
  timestamp = std::time(nullptr);
  dilithiumSignature = "";
  falconSignature = "";
  publicKeyDilithium.clear();
  publicKeyFalcon.clear();
  zkProof = std::vector<uint8_t>();
}

// ✅ Parameterized Constructor (Used When Mining Blocks)
Block::Block(int index, const std::string &previousHash,
             const std::vector<Transaction> &transactions,
             const std::string &minerAddress, int difficulty,
             uint64_t timestamp, uint64_t nonce)
    : index(index), previousHash(previousHash), transactions(transactions),
      minerAddress(minerAddress), difficulty(difficulty), timestamp(timestamp),
      nonce(nonce) {
  hash = calculateHash();
  keccakHash = Crypto::keccak256(hash);
  dilithiumSignature = "";
  falconSignature = "";
  publicKeyDilithium.clear();
  publicKeyFalcon.clear();
  zkProof = std::vector<uint8_t>();
}

// ✅ Copy Constructor
Block::Block(const Block &other)
    : index(other.index), previousHash(other.previousHash),
      transactions(other.transactions), hash(other.hash),
      minerAddress(other.minerAddress), nonce(other.nonce),
      timestamp(other.timestamp), blockSignature(other.blockSignature),
      keccakHash(other.keccakHash), difficulty(other.difficulty),
      dilithiumSignature(other.dilithiumSignature),
      falconSignature(other.falconSignature),
      publicKeyDilithium(other.publicKeyDilithium),
      publicKeyFalcon(other.publicKeyFalcon),
      zkProof(other.zkProof) // ✅ FIX: ensure zkProof is copied
{}

// ✅ Assignment Operator
Block &Block::operator=(const Block &other) {
    if (this != &other) {
        index = other.index;
        previousHash = other.previousHash;
        transactions = other.transactions;
        hash = other.hash;
        minerAddress = other.minerAddress;
        nonce = other.nonce;
        timestamp = other.timestamp;
        blockSignature = other.blockSignature;
        keccakHash = other.keccakHash;
        difficulty = other.difficulty;
        dilithiumSignature = other.dilithiumSignature;
        falconSignature = other.falconSignature;
        publicKeyDilithium = other.publicKeyDilithium;
        publicKeyFalcon = other.publicKeyFalcon;
        zkProof = other.zkProof; // ✅ FIX: ensure zkProof is copied
    }
    return *this;
}

//
void Block::computeKeccakHash() {
  keccakHash = Crypto::keccak256(hash); // ✅ Use Keccak hashing function
}
//
std::vector<unsigned char> Block::getSignatureMessage() const {
    std::vector<unsigned char> msg;

    // Serialize index (4 bytes)
    msg.push_back((index >> 24) & 0xFF);
    msg.push_back((index >> 16) & 0xFF);
    msg.push_back((index >> 8) & 0xFF);
    msg.push_back(index & 0xFF);

    // Append previousHash (decode from hex)
    auto prevHashBytes = Crypto::fromHex(previousHash);
    msg.insert(msg.end(), prevHashBytes.begin(), prevHashBytes.end());

    // Append transactions root (decode from hex)
    auto txRootBytes = Crypto::fromHex(getTransactionsHash());
    msg.insert(msg.end(), txRootBytes.begin(), txRootBytes.end());

    // Serialize timestamp (8 bytes)
    uint64_t ts = timestamp;
    for (int i = 7; i >= 0; --i) {
        msg.push_back((ts >> (i * 8)) & 0xFF);
    }

    // Serialize nonce (4 bytes)
    msg.push_back((nonce >> 24) & 0xFF);
    msg.push_back((nonce >> 16) & 0xFF);
    msg.push_back((nonce >> 8) & 0xFF);
    msg.push_back(nonce & 0xFF);

    // Hash all collected bytes
    std::string input(msg.begin(), msg.end());
    std::string hashed = Crypto::blake3Hash(input);

    if (hashed.size() != 32) {
        std::cerr << "❌ [getSignatureMessage] Error: hash length is " << hashed.size() << " instead of 32 bytes!\n";
    }

    return std::vector<unsigned char>(hashed.begin(), hashed.end());
}

// Calculate Hash
std::string Block::calculateHash() const {
  std::stringstream ss;
  ss << index << previousHash << getTransactionsHash() << timestamp << nonce;
  return Crypto::hybridHash(ss.str());
}

// ✅ Mine Block with Protobuf and RocksDB Storage
bool Block::mineBlock(int difficulty) {
    std::cout << "\n⏳ [mineBlock] Mining block for: " << minerAddress
              << " with difficulty: " << difficulty << "...\n";

    // === Step 1: PoW loop ===
    do {
        nonce++;
        if (nonce % 50000 == 0) {
            std::cout << "\r[Mining] Nonce: " << nonce << std::flush;
        }

        std::stringstream ss;
        ss << index << previousHash << computeTransactionsHash() << timestamp << nonce;
        hash = Crypto::hybridHash(ss.str());
    } while (hash.substr(0, difficulty) != std::string(difficulty, '0'));

    std::cout << "\n✅ [mineBlock] PoW Complete.\n";
    std::cout << "🔢 Final Nonce: " << nonce << "\n";
    std::cout << "🧬 Block Hash (BLAKE3): " << hash << "\n";

    // === Step 2: Keccak256 hash ===
    keccakHash = Crypto::keccak256(hash);
    std::cout << "✅ Keccak Hash: " << keccakHash << "\n";

    // === Step 3: zk-STARK Proof ===
    transactionsHash = computeTransactionsHash();   // ✅ fix: compute and store tx root
    setTransactionsHash(transactionsHash);          // ✅ critical: preserve for serialization
    std::cout << "🧬 Transactions Merkle Root: " << transactionsHash << "\n";

    std::string proofStr = WinterfellStark::generateProof(hash, previousHash, transactionsHash);
    zkProof = std::vector<uint8_t>(proofStr.begin(), proofStr.end());
    if (zkProof.size() < 64) {
        std::cerr << "❌ [mineBlock] zk-STARK proof too small (" << zkProof.size() << " bytes)\n";
        return false;
    }
    std::cout << "✅ zk-STARK Proof Generated. Size: " << zkProof.size() << " bytes\n";

    // === Step 4: Load Keys and Sign ===
    signBlock(minerAddress);

    // === Step 5: Validate signatures immediately ===
    if (dilithiumSignature.empty() || publicKeyDilithium.empty()) {
        std::cerr << "❌ [mineBlock] Critical: Dilithium signature/public key missing after signing. Aborting mining!\n";
        return false;
    }
    if (falconSignature.empty() || publicKeyFalcon.empty()) {
        std::cerr << "❌ [mineBlock] Critical: Falcon signature/public key missing after signing. Aborting mining!\n";
        return false;
    }

    std::cout << "✅ Block Signed Successfully.\n";
    return true;
}

// --- signBlock: hex-encode both signatures + public keys, sign 32-byte message only ---
void Block::signBlock(const std::string &minerAddress) {
    std::cout << "🔐 [DEBUG] Signing block with Dilithium and Falcon for: "
              << minerAddress << "\n";

    auto msgBytes = getSignatureMessage();
    if (msgBytes.size() != 32) {
        std::cerr << "❌ [ERROR] Message hash must be 32 bytes! Aborting signBlock.\n";
        return;
    }

    // === Dilithium ===
    if (!Crypto::fileExists("/root/.alyncoin/keys/" + minerAddress + "_dilithium.key")) {
        std::cout << "⚠️ Dilithium key missing. Generating...\n";
        Crypto::generateDilithiumKeys(minerAddress);
    }
    auto dkeys = Crypto::loadDilithiumKeys(minerAddress);
    if (dkeys.privateKey.empty() || dkeys.publicKey.empty()) {
        std::cerr << "❌ Failed to load Dilithium keys for: " << minerAddress << "\n";
        return;
    }
    auto sigD = Crypto::signWithDilithium(msgBytes, dkeys.privateKey);
    if (sigD.empty()) {
        std::cerr << "❌ Dilithium signature failed!\n";
        return;
    }
    dilithiumSignature = Crypto::toHex(sigD);  // ✅ signature is hex
    publicKeyDilithium = dkeys.publicKey;

    // === Falcon ===
    if (!Crypto::fileExists("/root/.alyncoin/keys/" + minerAddress + "_falcon.key")) {
        std::cout << "⚠️ Falcon key missing. Generating...\n";
        Crypto::generateFalconKeys(minerAddress);
    }
    auto fkeys = Crypto::loadFalconKeys(minerAddress);
    if (fkeys.privateKey.empty() || fkeys.publicKey.empty()) {
        std::cerr << "❌ Failed to load Falcon keys for: " << minerAddress << "\n";
        return;
    }
    auto sigF = Crypto::signWithFalcon(msgBytes, fkeys.privateKey);
    if (sigF.empty()) {
        std::cerr << "❌ Falcon signature failed!\n";
        return;
    }
    falconSignature = Crypto::toHex(sigF);  // ✅ signature is hex
    publicKeyFalcon = fkeys.publicKey;

    std::cout << "✅ [DEBUG] Block signatures applied.\n";
}

// ✅ Validate Block (PoW, zk-STARK, Transactions, Signatures)
bool Block::isValid(const std::string &prevHash, int expectedDifficulty) const {
    if (index == 0) {
        std::cout << "✅ Skipping full validation for Genesis block (index 0)\n";
        return true;
    }

    std::cout << "\n🔍 Validating Block Index: " << index
              << ", Miner: " << minerAddress << "\n";

    std::stringstream ss;
    ss << index << previousHash << getTransactionsHash() << timestamp << nonce;
    std::string recomputedHash = Crypto::hybridHash(ss.str());
    std::cout << "🔍 Recomputed Hash: " << recomputedHash << "\n";
    std::cout << "🔍 Stored Hash:     " << hash << "\n";

    if (recomputedHash != hash) {
        std::cerr << "❌ Invalid Block Hash!\n";
        return false;
    }

    {
        int diffToCheck = (expectedDifficulty > 0) ? expectedDifficulty : difficulty;
        if (hash.substr(0, diffToCheck) != std::string(diffToCheck, '0')) {
            std::cerr << "❌ Invalid PoW! Hash doesn't match difficulty " << diffToCheck << "\n";
            return false;
        }
    }

    if (Crypto::keccak256(hash) != keccakHash) {
        std::cerr << "❌ Keccak mismatch!\n";
        return false;
    }

    auto msgBytes = getSignatureMessage();
    if (msgBytes.size() != 32) {
        std::cerr << "❌ Signature message must be 32 bytes!\n";
        return false;
    }

    // — Dilithium Verification —
    {
        if (publicKeyDilithium.empty()) {
            std::cerr << "❌ Missing Dilithium public key!\n";
            return false;
        }
        std::vector<unsigned char> pubKeyDil;
        try {
            pubKeyDil = publicKeyDilithium;
        } catch (...) {
            std::cerr << "❌ Dilithium public key hex decode failed!\n";
            return false;
        }
        std::cout << "🧬 Dilithium Public Key Length: " << pubKeyDil.size() << "\n";

        std::vector<unsigned char> sigDil;
        try {
            sigDil = Crypto::fromHex(dilithiumSignature);
        } catch (...) {
            std::cerr << "❌ Dilithium signature hex decode failed!\n";
            return false;
        }
        std::cout << "🔏 Dilithium Signature Length: " << sigDil.size() << "\n";

        if (!Crypto::verifyWithDilithium(msgBytes, sigDil, pubKeyDil)) {
            std::cerr << "❌ Invalid Dilithium signature!\n";
            return false;
        }
        std::cout << "✅ Dilithium Signature Verified.\n";
    }

    // — Falcon Verification —
    {
        if (publicKeyFalcon.empty()) {
            std::cerr << "❌ Missing Falcon public key!\n";
            return false;
        }
        std::vector<unsigned char> pubKeyFal;
        try {
             pubKeyFal = publicKeyFalcon;
        } catch (...) {
            std::cerr << "❌ Falcon public key hex decode failed!\n";
            return false;
        }
        std::cout << "🦅 Falcon Public Key Length: " << pubKeyFal.size() << "\n";

        std::vector<unsigned char> sigFal;
        try {
            sigFal = Crypto::fromHex(falconSignature);
        } catch (...) {
            std::cerr << "❌ Falcon signature hex decode failed!\n";
            return false;
        }
        std::cout << "🔏 Falcon Signature Length: " << sigFal.size() << "\n";

        if (!Crypto::verifyWithFalcon(msgBytes, sigFal, pubKeyFal)) {
            std::cerr << "❌ Invalid Falcon signature!\n";
            return false;
        }
        std::cout << "✅ Falcon Signature Verified.\n";
    }

    for (auto &tx : transactions) {
        if (!tx.isValid(tx.getSenderPublicKeyDilithium(),
                        tx.getSenderPublicKeyFalcon()))
        {
            std::cerr << "❌ Invalid transaction in block!\n";
            return false;
        }
    }

    if (previousHash != prevHash) {
        std::cerr << "❌ Previous Hash Mismatch! expected: "
                  << prevHash << ", got: " << previousHash << "\n";
        return false;
    }

    {
        std::string txRoot = getTransactionsHash();
        if (!WinterfellStark::verifyProof(
                std::string(zkProof.begin(), zkProof.end()),
                hash, previousHash, txRoot
            ))
        {
            std::cerr << "❌ Invalid zk-STARK proof!\n";
            return false;
        }
    }

    std::cout << "✅ Block Validated Successfully.\n";
    return true;
}

//
double Block::getReward() const {
    return reward;
}

void Block::setReward(double r) {
    reward = r;
}

// ✅ Adaptive mining reward calculation
std::string Block::getTransactionsHash() const {
    if (!transactionsHash.empty()) {
        return transactionsHash;
    }

    if (transactions.empty()) {
        // Genesis or empty block — no need to log this
        return "";
    }

    std::stringstream ss;
    for (const auto& tx : transactions) {
        if (tx.getSender().empty() ||
            tx.getRecipient().empty() ||
            tx.getAmount() <= 0.0 ||
            tx.getSignatureDilithium().empty() ||
            tx.getSignatureFalcon().empty() ||
            tx.getZkProof().empty()) {
            std::cerr << "⚠️ [getTransactionsHash] Skipping invalid tx from Merkle root computation\n";
            continue;
        }
        ss << tx.getHash();
    }

    return Crypto::blake3(ss.str());
}

//
void Block::setTransactionsHash(const std::string &hash) {
    transactionsHash = hash;
}

std::string Block::computeTransactionsHash() const {
    std::string combined;
    for (const auto &tx : transactions) {
        combined += tx.getHash();  // Uses existing hashes
    }
    return Crypto::hybridHash(combined);  // Or Crypto::blake3()
}

// valid pow
bool Block::hasValidProofOfWork() const {
  if (difficulty <= 0) {
    std::cerr << "❌ Invalid difficulty value: " << difficulty << std::endl;
    return false;
  }

  std::string target(difficulty, '0'); // Generate target hash prefix
  if (hash.substr(0, difficulty) != target) {
    std::cerr << "❌ Proof-of-Work failed: " << hash
              << " does not meet difficulty " << difficulty << std::endl;
    return false;
  }
  return true;
}
//

// ✅ Convert Block to Protobuf-Compatible JSON (FIXED)
Json::Value Block::toJSON() const {
  Json::Value block;
  block["index"] = index;
  block["previousHash"] = previousHash;
  block["hash"] = hash;
  block["minerAddress"] = minerAddress;
  block["nonce"] = nonce;
  block["timestamp"] = static_cast<Json::UInt64>(timestamp);
  block["difficulty"] = difficulty;
  block["keccakHash"] = keccakHash;
  block["reward"] = reward;

  // ✅ Encode binary data to base64
  block["dilithiumSignature"] = Crypto::base64Encode(dilithiumSignature);
  block["falconSignature"] = Crypto::base64Encode(falconSignature);
  block["zkProof"] = Crypto::base64Encode(std::string(zkProof.begin(), zkProof.end()));
  block["publicKeyDilithium"] = Crypto::base64Encode(
    std::string(publicKeyDilithium.begin(), publicKeyDilithium.end()));

  block["publicKeyFalcon"] = Crypto::base64Encode(
    std::string(publicKeyFalcon.begin(), publicKeyFalcon.end()));

  Json::Value txArray(Json::arrayValue);
  for (const auto &tx : transactions) {
    txArray.append(tx.toJSON());
  }
  block["transactions"] = txArray;

  return block;
}

// ✅ Convert JSON to Block (Now Supports Protobuf Transactions)
Block Block::fromJSON(const Json::Value &blockJson) {
  std::vector<Transaction> txs;
  for (const auto &txJson : blockJson["transactions"]) {
    txs.push_back(Transaction::fromJSON(txJson));
  }

  Block block(
      blockJson["index"].asInt(),
      blockJson["previousHash"].asString(),
      txs,
      blockJson["minerAddress"].asString(),
      blockJson["difficulty"].asInt(),
      blockJson["timestamp"].asUInt64(),
      blockJson["nonce"].asUInt64());

  block.hash = blockJson["hash"].asString();
  block.keccakHash = blockJson.get("keccakHash", "").asString();
  block.reward = blockJson.get("reward", 0.0).asDouble();

  // ✅ Decode base64-encoded binary fields
  block.dilithiumSignature = Crypto::base64Decode(blockJson.get("dilithiumSignature", "").asString());
  block.falconSignature = Crypto::base64Decode(blockJson.get("falconSignature", "").asString());

  std::string zkStr = Crypto::base64Decode(blockJson.get("zkProof", "").asString());
  block.zkProof = std::vector<uint8_t>(zkStr.begin(), zkStr.end());

   {
    std::string decoded = Crypto::base64Decode(blockJson.get("publicKeyDilithium", "").asString());
    block.publicKeyDilithium = std::vector<unsigned char>(decoded.begin(), decoded.end());
  }
 {
    std::string decoded = Crypto::base64Decode(blockJson.get("publicKeyFalcon", "").asString());
    block.publicKeyFalcon = std::vector<unsigned char>(decoded.begin(), decoded.end());
  }
  return block;
}

// --- toProtobuf: always emit hex for zkProof, signatures & public keys ---
alyncoin::BlockProto Block::toProtobuf() const {
    alyncoin::BlockProto proto;

    std::string blkSig = blockSignature.empty()
                       ? Crypto::blake3(hash + dilithiumSignature + falconSignature)
                       : blockSignature;

    proto.set_index(index);
    proto.set_previous_hash(previousHash);
    proto.set_hash(hash);
    proto.set_miner_address(minerAddress);
    proto.set_nonce(nonce);
    proto.set_timestamp(timestamp);
    proto.set_difficulty(difficulty);
    proto.set_block_signature(blkSig);
    proto.set_keccak_hash(keccakHash);

    proto.set_tx_merkle_root(getTransactionsHash());
    proto.set_reward(reward);

    if (!zkProof.empty()) {
        proto.set_zk_stark_proof(Crypto::toHex(zkProof));
    }

    proto.set_dilithium_signature(dilithiumSignature);
    proto.set_falcon_signature(falconSignature);

    if (!publicKeyDilithium.empty()) {
        proto.set_public_key_dilithium(Crypto::toHex(
            std::vector<unsigned char>(publicKeyDilithium.begin(), publicKeyDilithium.end())
        ));
    }
    if (!publicKeyFalcon.empty()) {
        proto.set_public_key_falcon(Crypto::toHex(
            std::vector<unsigned char>(publicKeyFalcon.begin(), publicKeyFalcon.end())
        ));
    }

    // ✅ Only add valid transactions
    int kept = 0, skipped = 0;
    for (const auto &tx : transactions) {
        if (tx.getSender().empty() ||
            tx.getRecipient().empty() ||
            tx.getAmount() <= 0.0 ||
            tx.getSignatureDilithium().empty() ||
            tx.getSignatureFalcon().empty() ||
            tx.getZkProof().empty()) 
        {
            skipped++;
            continue;
        }
        *proto.add_transactions() = tx.toProto();
        kept++;
    }

    if (skipped > 0) {
        std::cerr << "⚠️ [toProtobuf] Skipped " << skipped << " invalid transaction(s) during block serialization.\n";
    }

    return proto;
}

//
Block Block::fromProto(const alyncoin::BlockProto& protoBlock, bool allowPartial) {
    Block newBlock;

    auto safeStr = [&](const std::string& val, const std::string& label, size_t maxLen = 10000) -> std::string {
        if (val.empty()) {
            if (!allowPartial)
                throw std::runtime_error("[fromProto] " + label + " is empty.");
            std::cerr << "⚠️ [fromProto] " << label << " is empty.\n";
            return "";
        }
        if (val.size() > maxLen) {
            std::cerr << "⚠️ [fromProto] " << label << " too long: " << val.size() << " bytes.\n";
            if (!allowPartial)
                throw std::runtime_error("[fromProto] " + label + " too long.");
            return "";
        }
        return val;
    };

    auto safeFromHex = [&](const std::string& hex, const std::string& label) -> std::vector<unsigned char> {
        if (hex.empty()) return {};
        if (hex.size() % 2 != 0) {
            std::cerr << "⚠️ [safeFromHex] " << label << " has odd length: " << hex.size() << "\n";
            return {};
        }
        try {
            return Crypto::fromHex(hex);
        } catch (...) {
            std::cerr << "⚠️ [safeFromHex] Failed decoding hex for " << label << "\n";
            return {};
        }
    };

    try {
        newBlock.index          = protoBlock.index();
        newBlock.previousHash   = safeStr(protoBlock.previous_hash(), "previous_hash");
        newBlock.hash           = safeStr(protoBlock.hash(), "hash");
        newBlock.minerAddress   = safeStr(protoBlock.miner_address(), "miner_address");
        newBlock.nonce          = protoBlock.nonce();
        newBlock.timestamp      = protoBlock.timestamp();
        newBlock.difficulty     = protoBlock.difficulty();
        newBlock.blockSignature = safeStr(protoBlock.block_signature(), "block_signature");
        newBlock.keccakHash     = safeStr(protoBlock.keccak_hash(), "keccak_hash");
        newBlock.reward         = protoBlock.has_reward() ? protoBlock.reward() : 0.0;

        // ✅ Preserve canonical tx_merkle_root
        std::string merkle = protoBlock.tx_merkle_root();
        if (merkle.empty()) {
            if (!allowPartial)
                throw std::runtime_error("[fromProto] tx_merkle_root is missing.");
            std::cerr << "⚠️ [fromProto] tx_merkle_root is empty.\n";
        }
        newBlock.transactionsHash = merkle;

        // zk-STARK proof
        if (!protoBlock.zk_stark_proof().empty()) {
            auto proof = safeFromHex(protoBlock.zk_stark_proof(), "zk_stark_proof");
            if (!proof.empty()) newBlock.zkProof = proof;
            else if (!allowPartial) throw std::runtime_error("[fromProto] zkProof decode failed.");
        }

        if (!protoBlock.dilithium_signature().empty()) {
            auto sig = safeFromHex(protoBlock.dilithium_signature(), "dilithium_signature");
            if (!sig.empty()) newBlock.dilithiumSignature = Crypto::toHex(sig);
            else if (!allowPartial) throw std::runtime_error("[fromProto] dilithium_signature decode failed.");
        }

        if (!protoBlock.falcon_signature().empty()) {
            auto sig = safeFromHex(protoBlock.falcon_signature(), "falcon_signature");
            if (!sig.empty()) newBlock.falconSignature = Crypto::toHex(sig);
            else if (!allowPartial) throw std::runtime_error("[fromProto] falcon_signature decode failed.");
        }

        if (!protoBlock.public_key_dilithium().empty()) {
            auto pub = safeFromHex(protoBlock.public_key_dilithium(), "public_key_dilithium");
            if (!pub.empty()) newBlock.publicKeyDilithium.assign(pub.begin(), pub.end());
            else if (!allowPartial) throw std::runtime_error("[fromProto] public_key_dilithium decode failed.");
        }

        if (!protoBlock.public_key_falcon().empty()) {
            auto pub = safeFromHex(protoBlock.public_key_falcon(), "public_key_falcon");
            if (!pub.empty()) newBlock.publicKeyFalcon.assign(pub.begin(), pub.end());
            else if (!allowPartial) throw std::runtime_error("[fromProto] public_key_falcon decode failed.");
        }

    } catch (const std::exception& ex) {
        std::cerr << "⚠️ [fromProto] Critical block-level error: " << ex.what() << "\n";
        if (!allowPartial) throw;
    }

    for (const auto& protoTx : protoBlock.transactions()) {
        try {
            Transaction tx = Transaction::fromProto(protoTx);
            if (tx.getSender().empty() || tx.getRecipient().empty() ||
                tx.getAmount() <= 0.0 || tx.getSignatureDilithium().empty() ||
                tx.getSignatureFalcon().empty() || tx.getZkProof().empty()) {
                std::cerr << "⚠️ [fromProto] Skipping incomplete transaction\n";
                continue;
            }
            newBlock.transactions.push_back(std::move(tx));
        } catch (const std::exception& ex) {
            std::cerr << "⚠️ [fromProto] Skipping tx: " << ex.what() << "\n";
            if (!allowPartial) throw;
        }
    }

    if (newBlock.transactions.empty()) {
        std::cerr << (allowPartial
            ? "⚠️ [fromProto] No valid transactions found. (AllowPartial = true)\n"
            : "⚠️ [fromProto] No transactions found, but proceeding (AllowPartial = false)\n");
    }

    return newBlock;
}

// Modify Block class to handle rollup block structure
std::string
Block::generateRollupProof(const std::vector<Transaction> &offChainTxs) {
  // This function would generate a proof for the rollup containing off-chain
  // transactions
  return WinterfellStark::generateProof(getHash(), previousHash,
                                        getTransactionsHash());
}
