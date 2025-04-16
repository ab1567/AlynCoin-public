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
  publicKeyDilithium = "";
  publicKeyFalcon = "";
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
  publicKeyDilithium = "";
  publicKeyFalcon = "";
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
    std::string input = hash + previousHash;
    std::string rawHash = Crypto::blake3Hash(input); // returns 32-byte raw
    return std::vector<unsigned char>(rawHash.begin(), rawHash.end());
}

// Calculate Hash
std::string Block::calculateHash() const {
  std::stringstream ss;
  ss << index << previousHash << getTransactionsHash() << timestamp << nonce;
  return Crypto::hybridHash(ss.str());
}

// ✅ **Mine Block with Protobuf and RocksDB Storage**
bool Block::mineBlock(int difficulty) {
    std::cout << "\n⏳ Mining block for: " << minerAddress
              << " with difficulty: " << difficulty << "...\n";

    // === Step 1: PoW loop ===
    do {
        nonce++;
        if (nonce % 50000 == 0) {
            std::cout << "\r[Mining] Nonce: " << nonce << std::flush;
        }

        std::stringstream ss;
        ss << index << previousHash << getTransactionsHash() << timestamp << nonce;
        hash = Crypto::hybridHash(ss.str());

    } while (hash.substr(0, difficulty) != std::string(difficulty, '0'));

    std::cout << "\n✅ PoW Complete.\n";
    std::cout << "🔢 Final Nonce: " << nonce << "\n";
    std::cout << "🧬 Block Hash (BLAKE3): " << hash << "\n";

    // === Step 2: Keccak256 hash ===
    keccakHash = Crypto::keccak256(hash);
    std::cout << "✅ Keccak Hash: " << keccakHash << "\n";

    // === Step 3: zk-STARK Proof ===
    std::string txRoot = getTransactionsHash();
    std::cout << "🧬 Transactions Merkle Root: " << txRoot << "\n";

    std::string proofStr = WinterfellStark::generateProof(hash, previousHash, txRoot);
    zkProof = std::vector<uint8_t>(proofStr.begin(), proofStr.end());
    if (zkProof.size() < 64) {
    std::cerr << "❌ zk-STARK proof size is too small (" << zkProof.size() << " bytes)\n";
    return false;
    }

    std::cout << "✅ zk-STARK Proof Generated. Size: " << zkProof.size() << " bytes\n";

    // === Step 4: Dilithium Signing ===
    std::string dilKeyPath = "/root/.alyncoin/keys/" + minerAddress + "_dilithium.key";
    if (!Crypto::fileExists(dilKeyPath)) {
        std::cout << "⚠️ Miner Dilithium private key missing. Generating...\n";
        Crypto::generateDilithiumKeys(minerAddress);
    }

    auto dilKeys = Crypto::loadDilithiumKeys(minerAddress);
    std::vector<unsigned char> privKeyDil = dilKeys.privateKey;
    std::vector<unsigned char> pubKeyDil = dilKeys.publicKey;

    if (privKeyDil.empty()) {
        std::cerr << "❌ Dilithium private key load failed!\n";
        return false;
    }

    std::vector<unsigned char> sigMsg = getSignatureMessage();
    std::cout << "📝 Signature Message Size: " << sigMsg.size() << "\n";
    std::cout << "🧬 Expected = 32 bytes\n";

    if (sigMsg.size() != 32) {
        std::cerr << "❌ Invalid signature message length: " << sigMsg.size() << " bytes\n";
        return false;
    }

    auto dilSig = Crypto::signWithDilithium(sigMsg, privKeyDil);
    if (dilSig.empty()) {
        std::cerr << "❌ Dilithium signature generation failed!\n";
        return false;
    }

    dilithiumSignature = Crypto::toHex(dilSig);
    publicKeyDilithium = std::string(pubKeyDil.begin(), pubKeyDil.end());
    std::cout << "✅ Dilithium Signature Length: " << dilSig.size() << " bytes\n";
    std::cout << "✅ Dilithium Public Key Length: " << pubKeyDil.size() << " bytes\n";
    std::cout << "✅ Block Signed with Dilithium Successfully.\n";

    // === Step 5: Falcon Signing ===
    std::string falconKeyPath = "/root/.alyncoin/keys/" + minerAddress + "_falcon.key";
    if (!Crypto::fileExists(falconKeyPath)) {
        std::cout << "⚠️ Miner Falcon private key missing. Generating...\n";
        Crypto::generateFalconKeys(minerAddress);
    }

    auto falKeys = Crypto::loadFalconKeys(minerAddress);
    std::vector<unsigned char> privKeyFalcon = falKeys.privateKey;
    std::vector<unsigned char> pubKeyFalconVec = falKeys.publicKey;

    if (privKeyFalcon.empty()) {
        std::cerr << "❌ Falcon private key load failed!\n";
        return false;
    }

    auto falSig = Crypto::signWithFalcon(sigMsg, privKeyFalcon);
    if (falSig.empty()) {
        std::cerr << "❌ Falcon signature generation failed!\n";
        return false;
    }

    falconSignature = Crypto::toHex(falSig);
    publicKeyFalcon = std::string(pubKeyFalconVec.begin(), pubKeyFalconVec.end());
    std::cout << "✅ Falcon Signature Length: " << falSig.size() << " bytes\n";
    std::cout << "✅ Falcon Public Key Length: " << pubKeyFalconVec.size() << " bytes\n";
    std::cout << "✅ Block Signed with Falcon Successfully.\n";

    return true;
}

//

void Block::signBlock(const std::string &minerAddress) {
    std::cout << "🔐 [DEBUG] Signing block with Dilithium and Falcon for: " << minerAddress << "\n";

    std::cout << "🔍 Block Hash: " << hash << "\n";
    std::cout << "🔍 Previous Hash: " << previousHash << "\n";

    std::vector<unsigned char> msgBytes = getSignatureMessage();

    if (msgBytes.size() != 32) {
        std::cerr << "❌ [ERROR] Message hash must be 32 bytes! Aborting signBlock.\n";
        return;
    }

    // === 🔑 Dilithium ===
    std::string dilithiumKeyPath = "/root/.alyncoin/keys/" + minerAddress + "_dilithium.key";
    if (!Crypto::fileExists(dilithiumKeyPath)) {
        std::cout << "⚠️ Dilithium key missing. Generating...\n";
        Crypto::generateDilithiumKeys(minerAddress);
    }

    auto dilKeys = Crypto::loadDilithiumKeys(minerAddress);
    if (dilKeys.privateKey.empty() || dilKeys.publicKey.empty()) {
        std::cerr << "❌ Failed to load Dilithium keys for: " << minerAddress << "\n";
        return;
    }

    std::vector<unsigned char> sigDil = Crypto::signWithDilithium(msgBytes, dilKeys.privateKey);
    if (sigDil.empty()) {
        std::cerr << "❌ Dilithium signature failed!\n";
        return;
    }

    dilithiumSignature = Crypto::toHex(sigDil);                    // 🔐 hex for signature
    publicKeyDilithium = std::string(dilKeys.publicKey.begin(),   // ✅ raw for pubkey
                                     dilKeys.publicKey.end());

    // === 🦅 Falcon ===
    std::string falconKeyPath = "/root/.alyncoin/keys/" + minerAddress + "_falcon.key";
    if (!Crypto::fileExists(falconKeyPath)) {
        std::cout << "⚠️ Falcon key missing. Generating...\n";
        Crypto::generateFalconKeys(minerAddress);
    }

    auto falKeys = Crypto::loadFalconKeys(minerAddress);
    if (falKeys.privateKey.empty() || falKeys.publicKey.empty()) {
        std::cerr << "❌ Failed to load Falcon keys for: " << minerAddress << "\n";
        return;
    }

    std::vector<unsigned char> sigFal = Crypto::signWithFalcon(msgBytes, falKeys.privateKey);
    if (sigFal.empty()) {
        std::cerr << "❌ Falcon signature failed!\n";
        return;
    }

    falconSignature = Crypto::toHex(sigFal);                      // 🔐 hex for signature
    publicKeyFalcon = std::string(falKeys.publicKey.begin(),     // ✅ raw for pubkey
                                  falKeys.publicKey.end());

    std::cout << "✅ [DEBUG] Block signatures applied.\n";
}

// ✅ Validate Block (Hybrid PoW, Transactions & Signature)
bool Block::isValid(const std::string &prevHash, int expectedDifficulty) const {
    std::cout << "\n🔍 Validating Block Index: " << index << ", Miner: " << minerAddress << "\n";

    // --- Recompute full block hash ---
    std::stringstream ss;
    ss << index << previousHash << getTransactionsHash() << timestamp << nonce;
    std::string recomputedHash = Crypto::hybridHash(ss.str());
    std::cout << "🔍 Recomputed Hash: " << recomputedHash << "\n";
    std::cout << "🔍 Stored Hash:     " << hash << "\n";

    if (recomputedHash != hash) {
        std::cerr << "❌ Invalid Block Hash!\n";
        return false;
    }

    // ✅ Skip PoW check for Genesis Block
    if (index != 0) {
        int diffToCheck = (expectedDifficulty > 0) ? expectedDifficulty : difficulty;
        if (hash.substr(0, diffToCheck) != std::string(diffToCheck, '0')) {
            std::cerr << "❌ Invalid PoW! Hash doesn't match difficulty " << diffToCheck << "\n";
            return false;
        }
    } else {
        std::cout << "✅ Skipping PoW check for Genesis Block.\n";
    }

    std::string recomputedKeccak = Crypto::keccak256(hash);
    std::cout << "🔍 Recomputed Keccak: " << recomputedKeccak << "\n";
    std::cout << "🔍 Stored Keccak:    " << keccakHash << "\n";

    if (recomputedKeccak != keccakHash) {
        std::cerr << "❌ Keccak Mismatch!\n";
        return false;
    }

    // ✅ Use canonical 32-byte signature message
    std::vector<unsigned char> msgBytes = getSignatureMessage();
    if (msgBytes.size() != 32) {
        std::cerr << "❌ Signature message must be 32 bytes!\n";
        return false;
    }

    // === ✅ Dilithium Signature Verification ===
    std::vector<unsigned char> pubKeyDil(publicKeyDilithium.begin(), publicKeyDilithium.end());
    std::cout << "🧬 Dilithium Public Key Length: " << pubKeyDil.size() << "\n";

    std::vector<unsigned char> sigDil;
    try {
        sigDil = Crypto::fromHex(dilithiumSignature);
        std::cout << "🔏 Dilithium Signature Length: " << sigDil.size() << "\n";
    } catch (...) {
        std::cerr << "❌ Invalid Dilithium Signature (Hex decode failed)!\n";
        return false;
    }

    if (!Crypto::verifyWithDilithium(msgBytes, sigDil, pubKeyDil)) {
        std::cerr << "❌ Invalid Dilithium Signature!\n";
        return false;
    } else {
        std::cout << "✅ Dilithium Signature Verified.\n";
    }

    // === ✅ Falcon Signature Verification ===
    std::vector<unsigned char> pubKeyFal(publicKeyFalcon.begin(), publicKeyFalcon.end());
    std::cout << "🦅 Falcon Public Key Length: " << pubKeyFal.size() << "\n";

    std::vector<unsigned char> sigFal;
    try {
        sigFal = Crypto::fromHex(falconSignature);
        std::cout << "🔏 Falcon Signature Length: " << sigFal.size() << "\n";
    } catch (...) {
        std::cerr << "❌ Invalid Falcon Signature (Hex decode failed)!\n";
        return false;
    }

    if (!Crypto::verifyWithFalcon(msgBytes, sigFal, pubKeyFal)) {
        std::cerr << "❌ Invalid Falcon Signature!\n";
        return false;
    } else {
        std::cout << "✅ Falcon Signature Verified.\n";
    }

    // === ✅ Validate All Transactions ===
    for (const auto &tx : transactions) {
        std::cout << "🔍 Validating Transaction from: " << tx.getSender() << "\n";
        if (!tx.isValid(tx.getSenderPublicKeyDilithium(), tx.getSenderPublicKeyFalcon())) {
            std::cerr << "❌ Invalid Transaction Detected. Hash: " << tx.getHash() << "\n";
            return false;
        }
    }

    if (previousHash != prevHash) {
        std::cerr << "❌ Previous Hash Mismatch! expected: " << prevHash << ", got: " << previousHash << "\n";
        return false;
    }

    // === 🔍 zk-STARK Proof Verification ===
    std::string txRoot = getTransactionsHash();
    std::cout << "🔍 Verifying zk-STARK Proof... Size: " << zkProof.size()
              << ", TxRoot: " << txRoot << "\n";

    if (!WinterfellStark::verifyProof(
            std::string(zkProof.begin(), zkProof.end()), hash, previousHash, txRoot)) {
        std::cerr << "❌ Invalid zk-STARK Proof!\n";
        return false;
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
//
std::string Block::getTransactionsHash() const {
  std::stringstream ss;
  for (const auto &tx : transactions) {
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
  block["publicKeyDilithium"] = Crypto::base64Encode(publicKeyDilithium);
  block["publicKeyFalcon"] = Crypto::base64Encode(publicKeyFalcon);

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

  block.publicKeyDilithium = Crypto::base64Decode(blockJson.get("publicKeyDilithium", "").asString());
  block.publicKeyFalcon = Crypto::base64Decode(blockJson.get("publicKeyFalcon", "").asString());

  return block;
}

//
alyncoin::BlockProto Block::toProtobuf() const {
    std::cout << "[DEBUG] 🧪 Entering toProtobuf() for block: " << hash
              << ", zkProof size: " << zkProof.size() << " bytes\n";

    alyncoin::BlockProto proto;
    proto.set_index(index);
    proto.set_previous_hash(previousHash);
    proto.set_hash(hash);
    proto.set_miner_address(minerAddress);
    proto.set_nonce(nonce);
    proto.set_timestamp(timestamp);
    proto.set_difficulty(difficulty);
    proto.set_block_signature(blockSignature);
    proto.set_keccak_hash(keccakHash);
    proto.set_tx_merkle_root(merkleRoot);
    proto.set_reward(reward);

    // ✅ zk-STARK proof (raw bytes)
    proto.set_zk_stark_proof(std::string(reinterpret_cast<const char*>(zkProof.data()), zkProof.size()));

    // ✅ PQ signatures and public keys — save as raw bytes
    proto.set_dilithium_signature(std::string(dilithiumSignature.begin(), dilithiumSignature.end()));
    proto.set_falcon_signature(std::string(falconSignature.begin(), falconSignature.end()));
    proto.set_public_key_dilithium(std::string(publicKeyDilithium.begin(), publicKeyDilithium.end()));
    proto.set_public_key_falcon(std::string(publicKeyFalcon.begin(), publicKeyFalcon.end()));

    for (const Transaction &tx : transactions) {
        *proto.add_transactions() = tx.toProto();
    }

    return proto;
}

//
Block Block::fromProto(const alyncoin::BlockProto &protoBlock) {
    Block newBlock;

    auto safeStr = [](const std::string &val, const std::string &label, size_t maxLen = 10000) -> std::string {
        if (val.size() > maxLen) {
            std::cerr << "❌ [fromProto] " << label << " too long (" << val.size() << " bytes). Skipping.\n";
            return "";
        }
        return val;
    };

    newBlock.setIndex(protoBlock.index());
    newBlock.setPreviousHash(safeStr(protoBlock.previous_hash(), "previous_hash", 1024));
    newBlock.setHash(safeStr(protoBlock.hash(), "hash", 1024));
    newBlock.setMinerAddress(safeStr(protoBlock.miner_address(), "miner_address", 4096));
    newBlock.setNonce(protoBlock.nonce());
    newBlock.setTimestamp(protoBlock.timestamp());
    newBlock.setDifficulty(protoBlock.difficulty());
    newBlock.setSignature(safeStr(protoBlock.block_signature(), "block_signature", 10000));
    newBlock.setKeccakHash(safeStr(protoBlock.keccak_hash(), "keccak_hash", 1024));
    newBlock.setReward(protoBlock.has_reward() ? protoBlock.reward() : 0.0);

    // ✅ zk-STARK proof
    const std::string &proofStr = protoBlock.zk_stark_proof();
    newBlock.zkProof.assign(proofStr.begin(), proofStr.end());

    // ✅ PQ signatures and pubkeys (raw binary)
    const std::string &dilSig = protoBlock.dilithium_signature();
    const std::string &falSig = protoBlock.falcon_signature();
    const std::string &dilPub = protoBlock.public_key_dilithium();
    const std::string &falPub = protoBlock.public_key_falcon();

    newBlock.dilithiumSignature.assign(dilSig.begin(), dilSig.end());
    newBlock.falconSignature.assign(falSig.begin(), falSig.end());
    newBlock.publicKeyDilithium.assign(dilPub.begin(), dilPub.end());
    newBlock.publicKeyFalcon.assign(falPub.begin(), falPub.end());

    // ✅ Transactions
    std::vector<Transaction> txs;
    for (const auto &protoTx : protoBlock.transactions()) {
        txs.push_back(Transaction::fromProto(protoTx));
    }
    newBlock.setTransactions(txs);

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
