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
      publicKeyFalcon(other.publicKeyFalcon) {}

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
  }
  return *this;
}
//
void Block::computeKeccakHash() {
  keccakHash = Crypto::keccak256(hash); // ✅ Use Keccak hashing function
}

// Getter for zkProof
std::string Block::getZkProof() const { return zkProof; }

// Setter for zkProof
void Block::setZkProof(const std::string &proof) { zkProof = proof; }

// Calculate Hash
std::string Block::calculateHash() const {
  std::stringstream ss;
  ss << index << previousHash << getTransactionsHash() << timestamp << nonce;
  return Crypto::hybridHash(ss.str());
}

// ✅ **Mine Block with Protobuf and RocksDB Storage**
bool Block::mineBlock(int difficulty) {
    std::cout << "⏳ Mining block for: " << minerAddress
              << " with difficulty: " << difficulty << "...\n";

    do {
        nonce++;
        if (nonce % 50000 == 0) {
            std::cout << "\r[Mining] Nonce: " << nonce << std::flush;
        }

        std::stringstream ss;
        ss << index << previousHash << getTransactionsHash() << timestamp << nonce;
        hash = Crypto::hybridHash(ss.str());
    } while (hash.substr(0, difficulty) != std::string(difficulty, '0'));

    std::cout << "\n✅ PoW Complete. BLAKE3 Hash: " << hash << "\n";

    keccakHash = Crypto::keccak256(hash);
    std::cout << "✅ Keccak Hash: " << keccakHash << "\n";

    std::string txRoot = getTransactionsHash();
    zkProof = WinterfellStark::generateProof(hash, previousHash, txRoot);
    std::cout << "✅ zk-STARK Proof Attached to Block.\n";

    // --- Dilithium key check + load
    std::string dilKeyPath = "/root/.alyncoin/keys/" + minerAddress + "_dilithium.key";
    if (!Crypto::fileExists(dilKeyPath)) {
        std::cout << "⚠️ Miner Dilithium private key missing. Generating...\n";
        Crypto::generateDilithiumKeys(minerAddress);
    }

    std::vector<unsigned char> privKeyDil = Crypto::loadDilithiumKeys(minerAddress).privateKey;
    if (privKeyDil.empty()) {
        std::cerr << "❌ Dilithium private key load failed!\n";
        return false;
    }

    std::vector<unsigned char> hashBytes = Crypto::fromHex(hash);
    dilithiumSignature = Crypto::toHex(Crypto::signWithDilithium(hashBytes, privKeyDil));
    publicKeyDilithium = Crypto::toHex(Crypto::getPublicKeyDilithium(minerAddress));

    std::cout << "✅ Block Signed with Dilithium Successfully.\n";

    // --- Falcon key check + load
    std::string falconKeyPath = "/root/.alyncoin/keys/" + minerAddress + "_falcon.key";
    if (!Crypto::fileExists(falconKeyPath)) {
        std::cout << "⚠️ Miner Falcon private key missing. Generating...\n";
        Crypto::generateFalconKeys(minerAddress);
    }

    std::vector<unsigned char> privKeyFalcon = Crypto::loadFalconKeys(minerAddress).privateKey;
    if (privKeyFalcon.empty()) {
        std::cerr << "❌ Falcon private key load failed!\n";
        return false;
    }

    falconSignature = Crypto::toHex(Crypto::signWithFalcon(hashBytes, privKeyFalcon));
    publicKeyFalcon = Crypto::toHex(Crypto::getPublicKeyFalcon(minerAddress));

    std::cout << "✅ Block Signed with Falcon Successfully.\n";

    return true;
}

//
bool Block::verifyBlockSignature(const std::string &publicKeyPath) const {
  std::cout << "[DEBUG] Verifying block signature using public key path: " << publicKeyPath << std::endl;

  if (!fs::exists(publicKeyPath)) {
    std::cerr << "❌ [ERROR] Public key not found: " << publicKeyPath << std::endl;
    return false;
  }

  std::ifstream pubFile(publicKeyPath, std::ios::binary);
  std::vector<unsigned char> pubKeyBytes((std::istreambuf_iterator<char>(pubFile)),
                                         std::istreambuf_iterator<char>());
  pubFile.close();

  std::vector<unsigned char> msgBytes(hash.begin(), hash.end());
  std::vector<unsigned char> sigBytes = Crypto::fromHex(blockSignature);

  if (pubKeyBytes.empty() || sigBytes.empty() || msgBytes.empty()) {
    std::cerr << "❌ [ERROR] Invalid inputs for verification.\n";
    return false;
  }

  // Use OpenSSL for signature verification (RSA)
  BIO *bio = BIO_new_mem_buf(pubKeyBytes.data(), pubKeyBytes.size());
  EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
  BIO_free(bio);

  if (!pkey) {
    std::cerr << "❌ [ERROR] Failed to parse public key.\n";
    return false;
  }

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pkey);
  EVP_DigestVerifyUpdate(ctx, msgBytes.data(), msgBytes.size());

  bool result = EVP_DigestVerifyFinal(ctx, sigBytes.data(), sigBytes.size()) == 1;

  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pkey);

  if (!result) {
    std::cerr << "❌ [ERROR] Signature verification failed!\n";
  } else {
    std::cout << "✅ [INFO] Signature verified successfully!\n";
  }

  return result;
}

//
void Block::signBlock(const std::string &minerPrivateKeyPath) {
  std::cout << "🔍 [DEBUG] Signing block using private key from: "
            << minerPrivateKeyPath << std::endl;

  // Load private key
  EVP_PKEY *privateKey = Crypto::loadPrivateKey(minerPrivateKeyPath);
  if (!privateKey) {
    std::cerr << "❌ [ERROR] Failed to load private key for signing!\n";
    return;
  }

  // Prepare data to sign (hash of block)
  std::string blockHash = this->getHash();
  std::cout << "🔍 [DEBUG] Block hash to sign: " << blockHash << std::endl;

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
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
    std::cerr << "❌ [ERROR] EVP_SignFinal failed: "
              << ERR_reason_error_string(ERR_get_error()) << "\n";
  } else {
    std::cout << "✅ [DEBUG] Block signed successfully! Signature size: "
              << sigLen << " bytes\n";

    // Base64 encode before setting
    std::string base64Sig =
        Crypto::base64Encode(std::string((char *)signature, sigLen));
    this->setSignature(base64Sig);
    std::cout << "✅ [DEBUG] Block signature Base64-encoded and set.\n";
  }

  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(privateKey);
}

// ✅ Validate Block (Hybrid PoW, Transactions & Signature)
bool Block::isValid(const std::string &prevHash) const {
  std::cout << "🔍 Validating Block Index: " << index << "\n";

  std::stringstream ss;
  ss << index << previousHash << getTransactionsHash() << timestamp << nonce;
  std::string recomputedHash = Crypto::hybridHash(ss.str());

  if (recomputedHash != hash) {
    std::cerr << "❌ Invalid Block Hash!\n";
    return false;
  }

  if (hash.substr(0, difficulty) != std::string(difficulty, '0')) {
    std::cerr << "❌ Invalid PoW!\n";
    return false;
  }

  std::string recomputedKeccak = Crypto::keccak256(hash);
  if (recomputedKeccak != keccakHash) {
    std::cerr << "❌ Keccak Mismatch!\n";
    return false;
  }

  std::vector<unsigned char> hashBytes;
  try {
    hashBytes = Crypto::fromHex(hash);
  } catch (const std::exception &ex) {
    std::cerr << "❌ Failed to decode block hash: " << ex.what() << "\n";
    return false;
  }

  std::vector<unsigned char> pubKeyDil = Crypto::getPublicKeyDilithium(minerAddress);
  std::vector<unsigned char> sigDil;
  try {
    sigDil = Crypto::fromHex(dilithiumSignature);
  } catch (...) {
    std::cerr << "❌ Invalid Dilithium Signature (Hex decode failed)!\n";
    return false;
  }

  if (!Crypto::verifyWithDilithium(hashBytes, sigDil, pubKeyDil)) {
    std::cerr << "❌ Invalid Dilithium Signature!\n";
    return false;
  }

  std::vector<unsigned char> pubKeyFal = Crypto::getPublicKeyFalcon(minerAddress);
  std::vector<unsigned char> sigFal;
  try {
    sigFal = Crypto::fromHex(falconSignature);
  } catch (...) {
    std::cerr << "❌ Invalid Falcon Signature (Hex decode failed)!\n";
    return false;
  }

  if (!Crypto::verifyWithFalcon(hashBytes, sigFal, pubKeyFal)) {
    std::cerr << "❌ Invalid Falcon Signature!\n";
    return false;
  }

  for (const auto &tx : transactions) {
    if (!tx.isValid(tx.getSenderPublicKeyDilithium(), tx.getSenderPublicKeyFalcon())) {
      std::cerr << "❌ Invalid Transaction Detected from: " << tx.getSender() << "\n";
      return false;
    }
  }

  if (previousHash != prevHash) {
    std::cerr << "❌ Previous Hash Mismatch!\n";
    return false;
  }

  std::string txRoot = getTransactionsHash();
  if (!WinterfellStark::verifyProof(zkProof, hash, previousHash, txRoot)) {
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
bool Block::deserializeFromProtobuf(const alyncoin::BlockProto &protoBlock) {
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

    // ✅ Load reward
    if (protoBlock.has_reward()) {
      reward = protoBlock.reward();
    } else {
      reward = 0.0;
    }

    transactions.clear();
    for (const auto &protoTx : protoBlock.transactions()) {
      Transaction tx;
      if (!tx.deserializeFromProtobuf(protoTx)) {
        std::cerr << "❌ [ERROR] Failed to deserialize transaction in block index: "
                  << index << "\n";
        return false;
      }
      transactions.push_back(tx);
    }

    // Deserialize zk-STARK proof
    setZkProof(protoBlock.zk_stark_proof());

    // Deserialize Dilithium and Falcon signatures
    dilithiumSignature = protoBlock.dilithium_signature();
    falconSignature = protoBlock.falcon_signature();
    publicKeyDilithium = protoBlock.public_key_dilithium();
    publicKeyFalcon = protoBlock.public_key_falcon();

    return true;
  } catch (const std::exception &e) {
    std::cerr << "❌ [ERROR] Exception during Block deserialization: "
              << e.what() << "\n";
    return false;
  }
}

//
void Block::serializeToProtobuf(alyncoin::BlockProto &proto) const {
  proto.set_index(index);
  proto.set_previous_hash(previousHash);
  proto.set_hash(hash);
  proto.set_miner_address(minerAddress);
  proto.set_nonce(nonce);
  proto.set_difficulty(difficulty);
  proto.set_timestamp(timestamp);
  proto.set_block_signature(blockSignature);
  proto.set_keccak_hash(keccakHash);
  proto.set_reward(reward);

  // Serialize transactions
  for (const auto &tx : transactions) {
    alyncoin::TransactionProto *protoTx = proto.add_transactions();
    tx.serializeToProtobuf(*protoTx);
  }

  // Serialize zk-STARK proof
  proto.set_zk_stark_proof(zkProof);

  // Serialize Dilithium and Falcon signatures
  proto.set_dilithium_signature(dilithiumSignature);
  proto.set_falcon_signature(falconSignature);
  proto.set_public_key_dilithium(publicKeyDilithium);
  proto.set_public_key_falcon(publicKeyFalcon);
}

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
  block["dilithiumSignature"] = dilithiumSignature;
  block["falconSignature"] = falconSignature;
  block["zkProof"] = zkProof;
  block["reward"] = reward;

  Json::Value txArray(Json::arrayValue);
  for (const auto &tx : transactions) {
    txArray.append(tx.toJSON());  // ✅ Uses updated Transaction::toJSON()
  }

  block["transactions"] = txArray;
  return block;
}

// ✅ Convert JSON to Block (Now Supports Protobuf Transactions)
Block Block::fromJSON(const Json::Value &blockJson) {
  std::vector<Transaction> txs;

  for (const auto &txJson : blockJson["transactions"]) {
    Transaction tx = Transaction::fromJSON(txJson);  // ✅ Use updated fromJSON
    txs.push_back(tx);
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
  block.dilithiumSignature = blockJson.get("dilithiumSignature", "").asString();
  block.falconSignature = blockJson.get("falconSignature", "").asString();
  block.zkProof = blockJson.get("zkProof", "").asString();

  return block;
}

//
Block Block::fromProto(const alyncoin::BlockProto &protoBlock) {
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
  newBlock.setReward(protoBlock.reward());

  // 🧠 Add the missing fields!
  newBlock.zkProof = protoBlock.zk_stark_proof();
  newBlock.dilithiumSignature = protoBlock.dilithium_signature();
  newBlock.falconSignature = protoBlock.falcon_signature();
  newBlock.publicKeyDilithium = protoBlock.public_key_dilithium();
  newBlock.publicKeyFalcon = protoBlock.public_key_falcon();

  std::vector<Transaction> txs;
  for (const auto &protoTx : protoBlock.transactions()) {
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

  // ✅ Store reward
  protoBlock.set_reward(reward);

  for (const auto &tx : transactions) {
    alyncoin::TransactionProto *protoTx = protoBlock.add_transactions();
    tx.serializeToProtobuf(*protoTx);
  }

  return protoBlock;
}

// Modify Block class to handle rollup block structure
std::string
Block::generateRollupProof(const std::vector<Transaction> &offChainTxs) {
  // This function would generate a proof for the rollup containing off-chain
  // transactions
  return WinterfellStark::generateProof(getHash(), previousHash,
                                        getTransactionsHash());
}
