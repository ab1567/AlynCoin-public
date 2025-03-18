#include "block.h"
#include <sstream>
#include <iomanip>
#include "blockchain.h"
#include "rocksdb/db.h"
#include <cstddef>
#include <iostream>
#include "crypto_utils.h"
#include "blake3.h"
#include "keccak.h"
#include <cmath>
#include <fstream>
#include <json/json.h>
#include <filesystem>
#include <thread>
#include "generated/block_protos.pb.h"
#include "generated/transaction_protos.pb.h"

namespace fs = std::filesystem;

const double BASE_BLOCK_REWARD = 10.0;  // Fixed block reward per mined block
const double MAX_BURN_RATE = 0.05;      // Max 5% burn rate
const double MIN_BURN_RATE = 0.01;      // Min 1% burn rate


// ✅ Default Constructor (No Arguments)
Block::Block() : index(0), previousHash("0000"), minerAddress("System"), hash(""), difficulty(4) {
    timestamp = std::time(nullptr);
}

// ✅ Parameterized Constructor (Used When Mining Blocks)
Block::Block(int index, const std::string& previousHash, const std::vector<Transaction>& transactions,
             const std::string& minerAddress, int difficulty, uint64_t timestamp, uint64_t nonce)
    : index(index), previousHash(previousHash), transactions(transactions),
      minerAddress(minerAddress), difficulty(difficulty), timestamp(timestamp), nonce(nonce) {
    hash = calculateHash();
    keccakHash = Crypto::keccak256(hash);
}
// ✅ Copy Constructor

Block::Block(const Block& other) : index(other.index), previousHash(other.previousHash), transactions(other.transactions),
    hash(other.hash), minerAddress(other.minerAddress), nonce(other.nonce), timestamp(other.timestamp), blockSignature(other.blockSignature),
    keccakHash(other.keccakHash), difficulty(other.difficulty) {}

// ✅ Assignment Operator
Block& Block::operator=(const Block& other) {
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
    }
    return *this;
}
//
void Block::computeKeccakHash() {
    keccakHash = Crypto::keccak256(hash);  // ✅ Use Keccak hashing function
}

// Calculate Hash
std::string Block::calculateHash() const {
    std::stringstream ss;
    ss << index << previousHash << timestamp << nonce << minerAddress;
    for (const auto& tx : transactions) {
        ss << tx.calculateHash();
    }
    return Crypto::hybridHash(ss.str());
}
// ✅ **Mine Block with Protobuf and RocksDB Storage**
bool Block::mineBlock(int difficulty) {
    std::cout << "⏳ Mining block for: " << minerAddress << " using Hybrid PoW...\n";
    do {
        nonce++;
        std::stringstream ss;
        ss << index << previousHash << getTransactionsHash() << timestamp << nonce;
        hash = Crypto::blake3(ss.str());
    } while (hash.substr(0, difficulty) != std::string(difficulty, '0'));

    std::cout << "✅ BLAKE3 PoW Complete. Hash: " << hash << "\n";

    // ✅ Generate Keccak hash (for later validation only)
    keccakHash = Crypto::keccak256(hash);
    std::cout << "✅ Keccak Hash Generated: " << keccakHash << "\n";

    // ✅ Sign block
    std::string minerKeyPath = "/root/.alyncoin/keys/" + minerAddress + "_private.pem";
    if (!Crypto::fileExists(minerKeyPath)) {
        std::cout << "⚠️ Miner key missing! Generating...\n";
        Crypto::generateKeysForUser(minerAddress);
    }
    setSignature(Crypto::signMessage(hash, minerKeyPath, true));
    std::cout << "✅ Block signed successfully.\n";

    return true;
}

//
bool Block::verifyBlockSignature(const std::string& publicKeyPath) const {
        std::cout << "[DEBUG] Verifying block signature using public key path: " << publicKeyPath << std::endl;
    if (!fs::exists(publicKeyPath)) {
        std::cerr << "❌ [ERROR] Public key not found: " << publicKeyPath << std::endl;
        return false;
    }

    bool isValid = Crypto::verifyMessage(publicKeyPath, blockSignature, getHash());

    if (!isValid) {
        std::cerr << "❌ [ERROR] Signature verification failed!" << std::endl;
    } else {
        std::cout << "✅ [INFO] Signature verified successfully!" << std::endl;
    }

    return isValid;
}

//
void Block::signBlock(const std::string& minerPrivateKeyPath) {
    std::cout << "🔍 [DEBUG] Signing block using private key from: " << minerPrivateKeyPath << std::endl;

    // Load private key
    EVP_PKEY* privateKey = Crypto::loadPrivateKey(minerPrivateKeyPath);
    if (!privateKey) {
        std::cerr << "❌ [ERROR] Failed to load private key for signing!\n";
        return;
    }

    // Prepare data to sign (hash of block)
    std::string blockHash = this->getHash();
    std::cout << "🔍 [DEBUG] Block hash to sign: " << blockHash << std::endl;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        std::cerr << "❌ [ERROR] Failed to create OpenSSL context!\n";
        EVP_PKEY_free(privateKey);
        return;
    }

    if (EVP_SignInit(ctx, EVP_sha256()) != 1) {
        std::cerr << "❌ [ERROR] EVP_SignInit failed!\n";
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(privateKey);
        return;
    }

    if (EVP_SignUpdate(ctx, blockHash.c_str(), blockHash.size()) != 1) {
        std::cerr << "❌ [ERROR] EVP_SignUpdate failed!\n";
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(privateKey);
        return;
    }

    unsigned char signature[256];
    unsigned int sigLen = 0;

    if (EVP_SignFinal(ctx, signature, &sigLen, privateKey) != 1) {
        std::cerr << "❌ [ERROR] EVP_SignFinal failed: " << ERR_reason_error_string(ERR_get_error()) << "\n";
    } else {
        std::cout << "✅ [DEBUG] Block signed successfully! Signature size: " << sigLen << " bytes\n";

        // Base64 encode before setting
        std::string base64Sig = Crypto::base64Encode(std::string((char*)signature, sigLen));
        this->setSignature(base64Sig);
        std::cout << "✅ [DEBUG] Block signature Base64-encoded and set.\n";
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(privateKey);
}

// ✅ Validate Block (Hybrid PoW, Transactions & Signature)
bool Block::isValid(const std::string& prevHash) const {
    std::cout << "🔍 Validating block index: " << index << "\n";

    // ✅ Recompute BLAKE3 hash
    std::stringstream ss;
    ss << index << previousHash << getTransactionsHash() << timestamp << nonce;
    std::string recomputedHash = Crypto::blake3(ss.str());

    if (recomputedHash != hash) {
        std::cout << "❌ Invalid block hash! Expected: " << recomputedHash << ", Found: " << hash << "\n";
        return false;
    }

    // ✅ Check Proof of Work
    if (hash.substr(0, difficulty) != std::string(difficulty, '0')) {
        std::cout << "❌ Invalid Proof-of-Work! Hash: " << hash << "\n";
        return false;
    }

    // ✅ Verify Keccak hash matches
    std::string recomputedKeccak = Crypto::keccak256(hash);
    if (recomputedKeccak != keccakHash) {
        std::cout << "❌ Keccak hash mismatch! Expected: " << recomputedKeccak << ", Found: " << keccakHash << "\n";
        return false;
    }
    std::cout << "✅ Keccak validation passed.\n";

    // ✅ Verify block signature
    std::string minerPubKeyPath = "/root/.alyncoin/keys/" + minerAddress + "_public.pem";
    if (!Crypto::verifyMessage(minerPubKeyPath, blockSignature, hash)) {
        std::cout << "❌ Invalid block signature!\n";
        return false;
    }

    // ✅ Verify transactions
    for (const auto& tx : transactions) {
        std::string senderKeyPath = "./keys/" + tx.getSender() + "_public.pem";
        if (!tx.isValid(senderKeyPath)) {
            std::cout << "❌ Invalid transaction found in block!\n";
            return false;
        }
    }

    // ✅ Check previous hash consistency
    if (previousHash != prevHash) {
        std::cout << "❌ Previous hash mismatch!\n";
        return false;
    }

    std::cout << "✅ Block index " << index << " is valid.\n";
    return true;
}

// ✅ Adaptive mining reward calculation
double Block::calculateMiningReward(int blockIndex, int recentTxCount) {
    double baseReward = INITIAL_REWARD * exp(-DECAY_RATE * blockIndex);
    
    // Dynamically adjust based on recent transactions
    double activityFactor = (recentTxCount < 10) ? 1.2 : (recentTxCount > 50) ? 0.8 : 1.0;

    return baseReward * activityFactor;
}
//
std::string Block::getTransactionsHash() const {
    std::stringstream ss;
    for (const auto& tx : transactions) {
        ss << tx.getHash();
    }
    return Crypto::blake3(ss.str());
}

// valid pow
bool Block::hasValidProofOfWork() const {
    if (difficulty <= 0) {
        std::cerr << "❌ Invalid difficulty value: " << difficulty << std::endl;
        return false;
    }

    std::string target(difficulty, '0'); // Generate target hash prefix
    if (hash.substr(0, difficulty) != target) {
        std::cerr << "❌ Proof-of-Work failed: " << hash << " does not meet difficulty " << difficulty << std::endl;
        return false;
    }
    return true;
}
//
bool Block::deserializeFromProtobuf(const alyncoin::BlockProto& protoBlock) {
    try {
        setIndex(protoBlock.index());
        setPreviousHash(protoBlock.previous_hash());
        setHash(protoBlock.hash());
        setMinerAddress(protoBlock.miner_address());
        setNonce(protoBlock.nonce());
        setTimestamp(protoBlock.timestamp());
        setDifficulty(protoBlock.difficulty());
        setSignature(protoBlock.block_signature());
        setKeccakHash(protoBlock.keccak_hash());

        transactions.clear();
        for (const auto& protoTx : protoBlock.transactions()) {
            Transaction tx;
            if (!tx.deserializeFromProtobuf(protoTx)) {
                std::cerr << "❌ [ERROR] Failed to deserialize transaction in block index: " << index << "\n";
                return false;
            }
            transactions.push_back(tx);
        }

        return true;
    } catch (const std::exception& e) {
        std::cerr << "❌ [ERROR] Exception during Block deserialization: " << e.what() << "\n";
        return false;
    }
}
//
void Block::serializeToProtobuf(alyncoin::BlockProto& proto) const {
    proto.set_index(index);
    proto.set_previous_hash(previousHash);
    proto.set_hash(hash);
    proto.set_miner_address(minerAddress);
    proto.set_nonce(nonce);
    proto.set_difficulty(difficulty);
    proto.set_timestamp(timestamp);
    proto.set_block_signature(blockSignature);

    for (const auto& tx : transactions) {
        alyncoin::TransactionProto* protoTx = proto.add_transactions();
        tx.serializeToProtobuf(*protoTx);
    }
}

// ✅ Convert Block to Protobuf-Compatible JSON (FIXED)
Json::Value Block::toJSON() const {
    Json::Value block;
    block["index"] = index;
    block["previousHash"] = previousHash;
    block["hash"] = hash;
    block["minerAddress"] = minerAddress;
    block["nonce"] = nonce;
    block["timestamp"] = timestamp;
    
    Json::Value txArray(Json::arrayValue);
    for (const auto& tx : transactions) {
        txArray.append(tx.toJSON());  // ✅ Proper serialization
    }
    block["transactions"] = txArray;

    return block;
}

// ✅ Convert JSON to Block (Now Supports Protobuf Transactions)
Block Block::fromJSON(const Json::Value& blockJson) {
    std::vector<Transaction> txs;

    for (const auto& txJson : blockJson["transactions"]) {
        alyncoin::TransactionProto protoTx;
        protoTx.ParseFromString(txJson.asString()); // ✅ Deserialize Protobuf format

        Transaction tx;
        tx.deserializeFromProtobuf(protoTx);
        txs.push_back(tx);
    }

    return Block(
        blockJson["index"].asInt(),
        blockJson["previousHash"].asString(),
        txs,
        blockJson["minerAddress"].asString(),
        blockJson["difficulty"].asInt(),  // ✅ Added missing argument
        blockJson["timestamp"].asUInt64(),  // ✅ Corrected uint64_t timestamp
        blockJson["nonce"].asUInt64()  // ✅ Corrected uint64_t nonce
    );
}
//
Block Block::fromProto(const alyncoin::BlockProto& protoBlock) {
    Block newBlock;

    newBlock.setIndex(protoBlock.index());
    newBlock.setPreviousHash(protoBlock.previous_hash());
    newBlock.setHash(protoBlock.hash());
    newBlock.setMinerAddress(protoBlock.miner_address());
    newBlock.setNonce(protoBlock.nonce());
    newBlock.setTimestamp(protoBlock.timestamp());
    newBlock.difficulty = protoBlock.difficulty();
    newBlock.setSignature(protoBlock.block_signature());
    newBlock.setKeccakHash(protoBlock.keccak_hash());

    std::vector<Transaction> txs;
    for (const auto& protoTx : protoBlock.transactions()) {
        Transaction tx = Transaction::fromProto(protoTx);
        txs.push_back(tx);
    }
    newBlock.setTransactions(txs);

    return newBlock;
}

//
alyncoin::BlockProto Block::toProtobuf() const {
    alyncoin::BlockProto protoBlock;
    protoBlock.set_index(index);
    protoBlock.set_timestamp(timestamp);
    protoBlock.set_previous_hash(previousHash);
    protoBlock.set_hash(hash);
    protoBlock.set_miner_address(minerAddress);
    protoBlock.set_nonce(nonce);
    protoBlock.set_difficulty(difficulty);
    protoBlock.set_block_signature(blockSignature);
    protoBlock.set_keccak_hash(keccakHash);

    for (const auto& tx : transactions) {
        alyncoin::TransactionProto* protoTx = protoBlock.add_transactions();
        tx.serializeToProtobuf(*protoTx);
    }

    return protoBlock;
}
