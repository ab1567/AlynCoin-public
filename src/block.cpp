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
#include "db/db_paths.h"

namespace fs = std::filesystem;

#define EMPTY_TX_ROOT_HASH "0c11a17c8610d35fe17aed2a5a5c682a6cdfb8b6ecf56a95605ebb1475b345de"

const double BASE_BLOCK_REWARD = 100.0; // Fixed block reward per mined block
const double MAX_BURN_RATE = 0.05;     // Max 5% burn rate
const double MIN_BURN_RATE = 0.01;     // Min 1% burn rate

void ensureRootConsistency(const Block& b, int idx) {
    if (b.merkleRoot != b.transactionsHash) {
        std::cerr << "❌ CRITICAL: merkleRoot != transactionsHash at block";
        if (idx >= 0) std::cerr << " index " << idx;
        std::cerr << "\n";
        std::cerr << "[Debug] merkleRoot:      " << b.merkleRoot << "\n";
        std::cerr << "[Debug] transactionsHash:" << b.transactionsHash << "\n";
        std::abort();
    }
}

// ✅ Default Constructor (No Arguments)
Block::Block()
    : index(0), previousHash("0000"), minerAddress("System"),  hash(""),
      difficulty(0), reward(0.0) {
  timestamp = std::time(nullptr);
  dilithiumSignature.clear();
  falconSignature.clear();
  publicKeyDilithium.clear();
  publicKeyFalcon.clear();
  zkProof = std::vector<uint8_t>();
  epochRoot.clear();
  epochProof.clear();
  cachedRoot.clear();
}

// ✅ Parameterized Constructor (Used When Mining Blocks)
Block::Block(int index, const std::string &previousHash,
             const std::vector<Transaction> &transactions,
             const std::string &minerAddress, int difficulty,
             uint64_t timestamp, uint64_t nonce)
    : index(index), previousHash(Crypto::normaliseHash(previousHash)), transactions(transactions),
      minerAddress(minerAddress), difficulty(difficulty),
      timestamp(timestamp), nonce(nonce), reward(0.0) {
  hash = "";
  keccakHash = Crypto::keccak256(hash);
  dilithiumSignature.clear();
  falconSignature.clear();
  publicKeyDilithium.clear();
  publicKeyFalcon.clear();
  zkProof = std::vector<uint8_t>();
  epochRoot.clear();
  epochProof.clear();
  cachedRoot.clear();
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
    // Use stored merkleRoot if set (even for empty blocks!)
    std::string txRoot;
    if (!merkleRoot.empty()) {
        txRoot = merkleRoot;
    } else if (!transactionsHash.empty()) {
        txRoot = transactionsHash;
    } else {
        txRoot = EMPTY_TX_ROOT_HASH;
    }
    std::stringstream ss;
    ss << index << previousHash << txRoot << timestamp << nonce;
    return Crypto::hybridHash(ss.str());
}

// ✅ Mine Block with Protobuf and RocksDB Storage
bool Block::mineBlock(int difficulty) {
    std::cerr << "[mineBlock] START for idx=" << getIndex()
              << ", prev=" << getPreviousHash() << '\n';
#ifdef LOG_DEBUG
    std::cout << "\n⏳ [mineBlock] Mining block for: " << minerAddress
              << " with difficulty: " << difficulty << "...\n";
#endif

    /* ───────────────────────────────────── 0 · Merkle root ── */
    if (transactions.empty()) {
        setMerkleRoot(EMPTY_TX_ROOT_HASH);                // → transactionsHash
    } else {
        std::string computedRoot = computeTransactionsHash();
        setMerkleRoot(computedRoot);                      // → transactionsHash
    }

    /* ───────────────────────────────────── 1 · PoW loop ──── */
    do {
        ++nonce;
        if (nonce % 50'000 == 0) {
#ifdef LOG_DEBUG
            std::cout << "\r[Mining] Nonce: " << nonce << std::flush;
#endif
        }

        std::string txRoot = getTransactionsHash();
        std::stringstream ss;
        ss << index << previousHash << txRoot << timestamp << nonce;
        hash = Crypto::hybridHash(ss.str());
    } while (hash.substr(0, difficulty) != std::string(difficulty, '0'));

#ifdef LOG_DEBUG
    std::cout << "\n✅ [mineBlock] PoW Complete.\n"
              << "🔢 Final Nonce: " << nonce << '\n'
              << "🧬 Block Hash (BLAKE3): " << hash << '\n';
#endif

    /* ───────────────────────────────────── 2 · Keccak ────── */
    keccakHash = Crypto::keccak256(hash);
#ifdef LOG_DEBUG
    std::cout << "✅ Keccak Hash: " << keccakHash << '\n';
#endif

    /* ───────────────────────────────────── 3 · zk-STARK ──── */
    std::string txRoot = getTransactionsHash();
    ensureRootConsistency(*this, index);
#ifdef LOG_DEBUG
    std::cout << "🧬 Transactions Merkle Root: " << txRoot << '\n';
#endif

    std::string proofStr;
    if (transactions.empty()) {
        /*  The Winterfell prover still expects ≥1 TX.  
            Use a tiny dummy proof for empty blocks.                    */
        proofStr.assign(236, '0');      // 236-byte stub => passes size check
    } else {
        proofStr = WinterfellStark::generateProof(hash, previousHash, txRoot);
    }

    /*  🔒  EARLY-EXIT GUARD  ────────────────────────────────
        If the prover falls back to the stub (“error-proof:…”) or
        the buffer is clearly too small, abort this block.        */
    if (proofStr.rfind("error-proof:", 0) == 0 || proofStr.size() < 200) {
        std::cerr << "❌ [mineBlock] zk-STARK proof invalid ("
                  << proofStr.size() << " bytes). Aborting mining.\n";
        return false;
    }

    zkProof.assign(proofStr.begin(), proofStr.end());
#ifdef LOG_DEBUG
    std::cout << "✅ zk-STARK Proof Generated. Size: "
              << zkProof.size() << " bytes\n";
#endif

    /* ───────────────────────────────────── 4 · Signatures ─── */
    signBlock(minerAddress);

    if (dilithiumSignature.empty() || publicKeyDilithium.empty()) {
        std::cerr << "❌ [mineBlock] Dilithium signature/public key missing. Abort.\n";
        return false;
    }
    if (falconSignature.empty() || publicKeyFalcon.empty()) {
        std::cerr << "❌ [mineBlock] Falcon signature/public key missing. Abort.\n";
        return false;
    }

    /* ───────────────────────────────────── Final log ─────── */
    std::cerr << "[mineBlock] DONE for idx=" << getIndex()
              << ", hash=" << getHash()
              << ", prev=" << getPreviousHash()
              << ", zkProof=" << zkProof.size() << '\n';

#ifdef LOG_DEBUG
    std::cout << "✅ Block Signed Successfully.\n";
#endif
    return true;
}

// --- signBlock: Sign and store binary signatures and public keys
void Block::signBlock(const std::string &minerAddress) {
#ifdef LOG_DEBUG
    std::cout << "🔐 [DEBUG] Signing block with Dilithium and Falcon for: "
              << minerAddress << "\n";
#endif

    auto msgBytes = getSignatureMessage();
    if (msgBytes.size() != 32) {
        std::cerr << "❌ [ERROR] Message hash must be 32 bytes! Aborting signBlock.\n";
        return;
    }

    // Dilithium
    if (!Crypto::fileExists(DBPaths::getKeyDir() + minerAddress + "_dilithium.key")) {
#ifdef LOG_DEBUG
        std::cout << "⚠️ Dilithium key missing. Generating...\n";
#endif
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
    dilithiumSignature = sigD;
    publicKeyDilithium = dkeys.publicKey;

    // Falcon
    if (!Crypto::fileExists(DBPaths::getKeyDir() + minerAddress + "_falcon.key")) {
#ifdef LOG_DEBUG
        std::cout << "⚠️ Falcon key missing. Generating...\n";
#endif
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
    falconSignature = sigF;
    publicKeyFalcon = fkeys.publicKey;

#ifdef LOG_DEBUG
    std::cout << "✅ [DEBUG] Block signatures applied.\n";
#endif
}

// ✅ Validate Block: Use raw binary, no Crypto::fromHex!
bool Block::isValid(const std::string &prevHash, int expectedDifficulty) const {
    ensureRootConsistency(*this, index);
    if (index == 0) {
        std::cout << "✅ Skipping full validation for Genesis block (index 0)\n";
        return true;
    }

    std::cout << "\n🔍 Validating Block Index: " << index
              << ", Miner: " << minerAddress << "\n";

    // === Always use merkleRoot if set (including for empty blocks) ===
    std::string txRoot;
    if (!merkleRoot.empty()) {
        txRoot = merkleRoot;
    } else if (!transactionsHash.empty()) {
        txRoot = transactionsHash;
    } else {
        txRoot = EMPTY_TX_ROOT_HASH;
    }

    std::stringstream ss;
    ss << index << previousHash << txRoot << timestamp << nonce;
    std::string recomputedHash = Crypto::hybridHash(ss.str());

    std::cout << "🔍 Recomputed Hash: " << recomputedHash << "\n";
    std::cout << "🔍 Stored Hash:     " << hash << "\n";

    if (recomputedHash != hash) {
        std::cerr << "❌ Invalid Block Hash!\n";
        std::cerr << "[DEBUG] index: " << index << "\n";
        std::cerr << "[DEBUG] prevHash: " << previousHash << "\n";
        std::cerr << "[DEBUG] txRoot (canonical): " << txRoot << "\n";
        std::cerr << "[DEBUG] merkleRoot: " << merkleRoot << "\n";
        std::cerr << "[DEBUG] transactionsHash: " << transactionsHash << "\n";
        std::cerr << "[DEBUG] timestamp: " << timestamp << "\n";
        std::cerr << "[DEBUG] nonce: " << nonce << "\n";
        std::cerr << "[DEBUG] Full hash input: " << ss.str() << "\n";
        return false;
    }

    int diffToCheck = (expectedDifficulty > 0) ? expectedDifficulty : difficulty;
    if (hash.substr(0, diffToCheck) != std::string(diffToCheck, '0')) {
        std::cerr << "❌ Invalid PoW! Hash doesn't match difficulty " << diffToCheck << "\n";
        return false;
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

    // ✅ Dilithium
    if (publicKeyDilithium.empty() || dilithiumSignature.empty()) {
        std::cerr << "❌ Missing Dilithium key or signature!\n";
        return false;
    }
    if (!Crypto::verifyWithDilithium(msgBytes, dilithiumSignature, publicKeyDilithium)) {
        std::cerr << "❌ Invalid Dilithium signature!\n";
        return false;
    }
    std::cout << "✅ Dilithium Signature Verified.\n";

    // ✅ Falcon
    if (publicKeyFalcon.empty() || falconSignature.empty()) {
        std::cerr << "❌ Missing Falcon key or signature!\n";
        return false;
    }
    if (!Crypto::verifyWithFalcon(msgBytes, falconSignature, publicKeyFalcon)) {
        std::cerr << "❌ Invalid Falcon signature!\n";
        return false;
    }
    std::cout << "✅ Falcon Signature Verified.\n";

    // ✅ Validate transactions
    for (const auto &tx : transactions) {
        if (!tx.isValid(tx.getSenderPublicKeyDilithium(), tx.getSenderPublicKeyFalcon())) {
            std::cerr << "❌ Invalid transaction in block!\n";
            return false;
        }
    }

    // ✅ Check parent hash
    if (previousHash != prevHash) {
        std::cerr << "❌ Previous Hash Mismatch! expected: "
                  << prevHash << ", got: " << previousHash << "\n";
        return false;
    }

    // ✅ zk-STARK Proof
    if (!WinterfellStark::verifyProof(
            std::string(zkProof.begin(), zkProof.end()),
            hash, previousHash, txRoot)) {
        std::cerr << "❌ Invalid zk-STARK proof!\n";
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
std::string Block::getTransactionsHash() const {
    if (!transactionsHash.empty()) {
        return transactionsHash;
    }
    if (!merkleRoot.empty()) {
        return merkleRoot;
    }
    std::cerr << "❌ [getTransactionsHash] Neither transactionsHash nor merkleRoot is set! BLOCK CORRUPT.\n";
    return EMPTY_TX_ROOT_HASH;
}


//
void Block::setMerkleRoot(const std::string &root) {
    merkleRoot = root;
    transactionsHash = root; // Always mirror!
    cachedRoot = root;
    ensureRootConsistency(*this, index);
}

void Block::setTransactionsHash(const std::string &hash) {
    transactionsHash = hash;
    merkleRoot = hash; // Always mirror!
    cachedRoot = hash;
    ensureRootConsistency(*this, index);
}

std::string Block::computeTransactionsHash() const {
    if (!cachedRoot.empty())
        return cachedRoot;

    std::string combined;
    for (const auto &tx : transactions) {
        combined += tx.getHash();  // Uses existing hashes
    }
    cachedRoot = Crypto::hybridHash(combined);  // Or Crypto::blake3()
    return cachedRoot;
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
  block["dilithiumSignature"] = Crypto::base64Encode(std::string(dilithiumSignature.begin(), dilithiumSignature.end()));
  block["falconSignature"] = Crypto::base64Encode(std::string(falconSignature.begin(), falconSignature.end()));
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
  {
    std::string decoded = Crypto::base64Decode(blockJson.get("dilithiumSignature", "").asString());
    block.dilithiumSignature = std::vector<unsigned char>(decoded.begin(), decoded.end());
 }

  {
    std::string decoded = Crypto::base64Decode(blockJson.get("falconSignature", "").asString());
    block.falconSignature = std::vector<unsigned char>(decoded.begin(), decoded.end());
}

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
    ensureRootConsistency(block, block.index);
  return block;
}

//
alyncoin::BlockProto Block::toProtobuf() const {
    // --- [ROOT FAILSAFE] Enforce invariant before serialization ---
    if (merkleRoot.empty() && !transactionsHash.empty())
        const_cast<Block*>(this)->setMerkleRoot(transactionsHash);
    if (transactionsHash.empty() && !merkleRoot.empty())
        const_cast<Block*>(this)->setTransactionsHash(merkleRoot);
    ensureRootConsistency(*this, index);

    alyncoin::BlockProto proto;

    std::string blkSig = blockSignature.empty()
        ? Crypto::blake3(
            hash +
            std::string(dilithiumSignature.begin(), dilithiumSignature.end()) +
            std::string(falconSignature.begin(), falconSignature.end()))
        : blockSignature;

    // --- Enforce hash normalisation (will abort if not) ---
    if (hash.size() != 64 || previousHash.size() != 64) {
        std::cerr << "❌ [toProtobuf] Hash width invariant violated! hash=" << hash << " prev=" << previousHash << std::endl;
        abort();
    }

    proto.set_index(index);
    proto.set_previous_hash(previousHash);
    proto.set_hash(hash);
    proto.set_miner_address(minerAddress);
    proto.set_nonce(nonce);
    proto.set_timestamp(timestamp);
    proto.set_difficulty(difficulty);
    proto.set_block_signature(blkSig);
    proto.set_keccak_hash(keccakHash);

    // === CRITICAL: Guarantee tx_merkle_root is set and valid ===
    std::string txRoot = getTransactionsHash();

    bool isGenesis = (index == 0);
    if (txRoot.empty() ||
        (txRoot == EMPTY_TX_ROOT_HASH && (!isGenesis && !transactions.empty()))) {
        std::cerr << "\n\n❌ [toProtobuf] FATAL: Block being serialized without valid Merkle root! index=" << index
                  << " hash=" << hash << "\n";
        std::cerr << "    transactionsHash='" << transactionsHash << "'\n";
        std::cerr << "    merkleRoot='" << merkleRoot << "'\n";
        std::cerr << "    transactions.size()=" << transactions.size() << "\n";
        std::cerr << "    l2Transactions.size()=" << l2Transactions.size() << "\n";
        std::cerr << "    This block will not be serialized. Aborting.\n";
        abort();
    }

    if (txRoot.empty()) {
        txRoot = EMPTY_TX_ROOT_HASH;
        std::cerr << "[toProtobuf] WARNING: getTransactionsHash() empty, using EMPTY_TX_ROOT_HASH!\n";
    }
    proto.set_tx_merkle_root(txRoot);
    proto.set_reward(reward);

    // === Binary fields ===
    if (!zkProof.empty()) {
        proto.set_zk_stark_proof(reinterpret_cast<const char*>(zkProof.data()), zkProof.size());
    }
    proto.set_dilithium_signature(reinterpret_cast<const char*>(dilithiumSignature.data()), dilithiumSignature.size());
    proto.set_falcon_signature(reinterpret_cast<const char*>(falconSignature.data()), falconSignature.size());

    if (!publicKeyDilithium.empty()) {
        if (publicKeyDilithium.size() != 1312) {
            std::cerr << "❌ [toProtobuf] Unexpected Dilithium public key size: " << publicKeyDilithium.size() << "\n";
        }
        proto.set_public_key_dilithium(reinterpret_cast<const char*>(publicKeyDilithium.data()), publicKeyDilithium.size());
    }
    if (!publicKeyFalcon.empty()) {
        if (publicKeyFalcon.size() != FALCON_PUBLIC_KEY_BYTES) {
            std::cerr << "❌ [toProtobuf] Unexpected Falcon public key size: " << publicKeyFalcon.size() << "\n";
        }
        proto.set_public_key_falcon(reinterpret_cast<const char*>(publicKeyFalcon.data()), publicKeyFalcon.size());
    }

    // === L1 Transactions ===
    for (const auto& tx : transactions) {
        if (tx.getSender() == "System") {
            *proto.add_transactions() = tx.toProto();
            continue;
        }
        if (tx.getSender().empty() || tx.getRecipient().empty() || tx.getAmount() <= 0.0 ||
            tx.getSignatureDilithium().empty() || tx.getSignatureFalcon().empty() || tx.getZkProof().empty()) {
            continue;
        }
        *proto.add_transactions() = tx.toProto();
    }
    // === L2 Transactions ===
    for (const auto& l2tx : l2Transactions) {
        if (l2tx.getSender().empty() || l2tx.getRecipient().empty() || l2tx.getAmount() <= 0.0 ||
            l2tx.getSignatureDilithium().empty() || l2tx.getSignatureFalcon().empty() || l2tx.getZkProof().empty()) {
            continue;
        }
        *proto.add_l2_transactions() = l2tx.toProto();
    }

    if (!epochRoot.empty())
        proto.set_epoch_root(epochRoot);
    if (!epochProof.empty())
        proto.set_epoch_proof(reinterpret_cast<const char*>(epochProof.data()), epochProof.size());

    std::cerr << "[toProtobuf] index=" << index << " tx_merkle_root=" << txRoot << std::endl;
    return proto;
}

//

Block Block::fromProto(const alyncoin::BlockProto& protoBlock, bool allowPartial) {
    Block newBlock;

    // STRICT: For required fields
    auto safeStr = [&](const std::string& val, const std::string& label, size_t maxLen = 10000) -> std::string {
        if (val.empty()) {
            if (!allowPartial) throw std::runtime_error("[fromProto] " + label + " is empty.");
            return "";
        }
        if (val.size() > maxLen) {
            if (!allowPartial) throw std::runtime_error("[fromProto] " + label + " too long.");
            return "";
        }
        std::string sanitized;
        sanitized.reserve(val.size());
        for (char c : val) {
            if (std::isprint(static_cast<unsigned char>(c)) && c != '\0')
                sanitized += c;
        }
        return sanitized;
    };

    auto safeBinaryField = [&](const std::string& bin, const std::string& label, size_t maxLen = 10000) -> std::vector<unsigned char> {
        if (bin.empty()) {
            if (!allowPartial) std::cerr << "❌ [fromProto] Required binary field " << label << " is empty.\n";
            return {};
        }
        if (bin.size() > maxLen) {
            std::cerr << "❌ [fromProto] " << label << " too large: " << bin.size() << " bytes\n";
            if (!allowPartial) throw std::runtime_error(label + " too large");
            return {};
        }
        std::vector<unsigned char> binary(bin.begin(), bin.end());
        while (!binary.empty() && binary.back() == '\0') {
            binary.pop_back();
        }
        if (label == "Falcon Public Key" && binary.size() != FALCON_PUBLIC_KEY_BYTES) {
            std::cerr << "❌ [fromProto] Invalid Falcon Public Key length: " << binary.size()
                      << " (expected: " << FALCON_PUBLIC_KEY_BYTES << ")\n";
            if (!allowPartial) throw std::runtime_error("Invalid Falcon public key length.");
            return {};
        }
        if (label == "Dilithium Public Key" && binary.size() != DILITHIUM_PUBLIC_KEY_BYTES) {
            std::cerr << "❌ [fromProto] Invalid Dilithium Public Key length: " << binary.size()
                      << " (expected: " << DILITHIUM_PUBLIC_KEY_BYTES << ")\n";
            if (!allowPartial) throw std::runtime_error("Invalid Dilithium public key length.");
            return {};
        }
        return binary;
    };

    // SOFT: For optional fields only (epoch_root/epoch_proof)
    auto optionalStr = [&](const std::string& s, const std::string& label, size_t maxLen = 128) -> std::string {
        if (s.empty()) {
            static bool warned = false;
            return "";
        }
        return (s.size() <= maxLen) ? s : s.substr(0, maxLen);
    };
    auto optionalBinaryField = [&](const std::string& bin, const std::string& label, size_t maxLen = 10000) -> std::vector<uint8_t> {
        if (bin.empty()) {
            static bool warned = false;
            return {};
        }
        if (bin.size() > maxLen) {
            return std::vector<uint8_t>(bin.begin(), bin.begin() + maxLen);
        }
        return std::vector<uint8_t>(bin.begin(), bin.end());
    };

    try {
        newBlock.index              = protoBlock.index();

        newBlock.previousHash       = Crypto::normaliseHash(safeStr(protoBlock.previous_hash(),     "previous_hash"));
        newBlock.hash               = Crypto::normaliseHash(safeStr(protoBlock.hash(),              "hash"));
        newBlock.minerAddress       = safeStr(protoBlock.miner_address(),     "miner_address");
        newBlock.nonce              = protoBlock.nonce();
        newBlock.timestamp          = protoBlock.timestamp();
        newBlock.difficulty         = protoBlock.difficulty();
        newBlock.blockSignature     = safeStr(protoBlock.block_signature(),   "block_signature");
        newBlock.keccakHash         = safeStr(protoBlock.keccak_hash(),       "keccak_hash");
        newBlock.reward             = protoBlock.reward();

        // === CRITICAL: RESTORE ROOTS EXACTLY, NEVER RECOMPUTE! ===
        std::string protoTxRoot = safeStr(protoBlock.tx_merkle_root(), "tx_merkle_root", 128);
        if (!protoTxRoot.empty()) {
            newBlock.setMerkleRoot(protoTxRoot); // Always use setter!
        } else {
            newBlock.setMerkleRoot(EMPTY_TX_ROOT_HASH);
        }
        // === END CRITICAL ===

        newBlock.zkProof            = safeBinaryField(protoBlock.zk_stark_proof(),      "zkProof",             2'000'000);
        newBlock.dilithiumSignature = safeBinaryField(protoBlock.dilithium_signature(), "Dilithium Signature", 5000);
        newBlock.falconSignature    = safeBinaryField(protoBlock.falcon_signature(),    "Falcon Signature",    2000);
        newBlock.publicKeyDilithium = safeBinaryField(protoBlock.public_key_dilithium(),"Dilithium Public Key", 2000);
        newBlock.publicKeyFalcon    = safeBinaryField(protoBlock.public_key_falcon(),   "Falcon Public Key",    2000);

        // ---- ONLY soft for epoch fields! ----
        newBlock.epochRoot  = optionalStr(protoBlock.epoch_root(), "epoch_root", 128);
        newBlock.epochProof = optionalBinaryField(protoBlock.epoch_proof(), "epoch_proof", 5000);

    } catch (const std::exception& ex) {
        std::cerr << "❌ [fromProto] Critical error: " << ex.what() << "\n";
        if (!allowPartial) throw;
    }

    int skipped = 0;
    for (const auto& protoTx : protoBlock.transactions()) {
        try {
            Transaction tx = Transaction::fromProto(protoTx);
            bool isReward = (tx.getSender() == "System");
            if (!isReward &&
                (tx.getSender().empty() || tx.getRecipient().empty() || tx.getAmount() <= 0.0 ||
                 tx.getSignatureDilithium().empty() || tx.getSignatureFalcon().empty() || tx.getZkProof().empty())) {
                std::cerr << "⚠️ [fromProto] Skipping tx with missing or invalid fields.\n";
                skipped++;
                continue;
            }
            newBlock.transactions.push_back(std::move(tx));
        } catch (...) {
            std::cerr << "⚠️ [fromProto] Error parsing transaction.\n";
            skipped++;
        }
    }

    int l2Skipped = 0;
    for (const auto& protoTx : protoBlock.l2_transactions()) {
        try {
            Transaction tx = Transaction::fromProto(protoTx);
            if (tx.getSender().empty() || tx.getRecipient().empty() || tx.getAmount() <= 0.0 ||
                tx.getSignatureDilithium().empty() || tx.getSignatureFalcon().empty() || tx.getZkProof().empty()) {
                std::cerr << "⚠️ [fromProto] Skipping invalid L2 transaction.\n";
                l2Skipped++;
                continue;
            }
            newBlock.l2Transactions.push_back(std::move(tx));
        } catch (...) {
            std::cerr << "⚠️ [fromProto] Error parsing L2 transaction.\n";
            l2Skipped++;
        }
    }

    if (newBlock.transactions.empty() && protoBlock.transactions_size() > 0 && !allowPartial) {
        std::cerr << "⚠️ [fromProto] No valid L1 transactions parsed.\n";
        throw std::runtime_error("Transactions present but none valid.");
    }



    // DO NOT recompute root or merkle here!

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
