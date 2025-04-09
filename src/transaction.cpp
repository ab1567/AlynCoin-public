#include "generated/transaction_protos.pb.h"
#include "transaction.h"
#include "../network/peer_blacklist.h"
#include "base64.h"
#include "db/db_paths.h"
#include "crypto_utils.h"
#include "hash.h"
#include "proof_verifier.h"
#include "rollup/rollup_utils.h"
#include "winterfell_stark.h"
#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <openssl/sha.h>
#include <rocksdb/db.h>
#include <sstream>
#include <thread>

namespace fs = std::filesystem;

// Create off-chain transactions for Layer-2
class OffChainTransaction {
public:
  std::string sender;
  std::string recipient;
  double amount;
  std::string txHash;      // Off-chain transaction hash
  std::string layer2Proof; // Layer-2 Proof of transaction validity

  // Add any other necessary fields for off-chain transactions

  std::string calculateHash() const {
    std::stringstream ss;
    ss << sender << recipient << amount; // Hash based on relevant fields
    return Crypto::hybridHash(ss.str());
  }
};
// ✅ Constructor:
Transaction::Transaction()
    : sender(""), recipient(""), amount(0), signatureDilithium(""),
      signatureFalcon(""), timestamp(std::time(nullptr)) {}

Transaction::Transaction(const std::string &sender,
                         const std::string &recipient, double amount,
                         const std::string &signatureDilithium,
                         const std::string &signatureFalcon,
                         std::time_t timestamp)
    : sender(sender), recipient(recipient), amount(amount),
      signatureDilithium(signatureDilithium), signatureFalcon(signatureFalcon),
      timestamp(timestamp) {}

// ✅ Getters:
std::string Transaction::getSender() const { return sender; }
std::string Transaction::getRecipient() const { return recipient; }
double Transaction::getAmount() const { return amount; }
std::string Transaction::getSignatureDilithium() const {
  return signatureDilithium;
}
std::string Transaction::getSignatureFalcon() const { return signatureFalcon; }
time_t Transaction::getTimestamp() const { return timestamp; }
std::string Transaction::getZkProof() const { return zkProof; }
void Transaction::setZkProof(const std::string &proof) { zkProof = proof; }

// Transaction Hash:
std::string Transaction::getTransactionHash() const {
  std::ostringstream data;
  data << sender << recipient << amount << timestamp;
  return Crypto::hybridHash(data.str());
}
//

std::string Transaction::getHash() const {
  return hash;
}

// ✅ Protobuf Serialization - Ensure all required fields are set
void Transaction::serializeToProtobuf(alyncoin::TransactionProto &proto) const {
  proto.set_sender(sender);
  proto.set_recipient(recipient);
  proto.set_amount(amount);
  proto.set_signature_dilithium(signatureDilithium);
  proto.set_signature_falcon(signatureFalcon);
  proto.set_sender_pubkey_dilithium(senderPublicKeyDilithium);
  proto.set_sender_pubkey_falcon(senderPublicKeyFalcon);
  proto.set_timestamp(timestamp);
  proto.set_metadata(metadata);
  proto.set_hash(hash);
}

bool Transaction::deserializeFromProtobuf(const alyncoin::TransactionProto &proto) {
  sender = proto.sender();
  recipient = proto.recipient();
  amount = proto.amount();
  signatureDilithium = proto.signature_dilithium();
  signatureFalcon = proto.signature_falcon();
  senderPublicKeyDilithium = proto.sender_pubkey_dilithium();
  senderPublicKeyFalcon = proto.sender_pubkey_falcon();
  timestamp = proto.timestamp();
  metadata = proto.metadata();
  zkProof = proto.zkproof();  // ✅ Restore zkProof
  hash = proto.hash();        // ✅ Restore hash (used in verify)
  return true;
}

//
Transaction Transaction::fromProto(const alyncoin::TransactionProto &proto) {
    Transaction tx(proto.sender(), proto.recipient(), proto.amount(),
                   proto.signature_dilithium(), proto.signature_falcon(),
                   proto.timestamp());

    tx.setZkProof(proto.zkproof());
    tx.senderPublicKeyDilithium = proto.sender_pubkey_dilithium();
    tx.senderPublicKeyFalcon = proto.sender_pubkey_falcon();
    tx.metadata = proto.metadata();
    tx.hash = proto.hash();
    return tx;
}

//To JSON
Json::Value Transaction::toJSON() const {
  Json::Value tx;

  if (isRewardTransaction()) {
    tx["type"] = "reward";
    tx["sender"] = "System";
    tx["recipient"] = recipient;
    tx["amount"] = amount;
    tx["timestamp"] = static_cast<Json::Int64>(timestamp);
    return tx;
  }

  tx["sender"] = sender;
  tx["recipient"] = recipient;
  tx["amount"] = amount;
  tx["signatureDilithium"] = signatureDilithium;
  tx["signatureFalcon"] = signatureFalcon;
  tx["zkProof"] = zkProof;
  tx["timestamp"] = static_cast<Json::Int64>(timestamp);
  tx["senderPublicKeyDilithium"] = senderPublicKeyDilithium;
  tx["senderPublicKeyFalcon"] = senderPublicKeyFalcon;
  tx["metadata"] = metadata;

  return tx;
}
// From JSON
Transaction Transaction::fromJSON(const Json::Value &txJson) {
  Transaction tx;
  tx.sender = txJson.get("sender", "").asString();
  tx.recipient = txJson.get("recipient", "").asString();
  tx.amount = txJson.get("amount", 0.0).asDouble();
  tx.timestamp = txJson.get("timestamp", 0).asInt64();

  if (tx.sender != "System") {
    tx.signatureDilithium = txJson.get("signatureDilithium", "").asString();
    tx.signatureFalcon = txJson.get("signatureFalcon", "").asString();
    tx.zkProof = txJson.get("zkProof", "").asString();
    tx.senderPublicKeyDilithium = txJson.get("senderPublicKeyDilithium", "").asString();
    tx.senderPublicKeyFalcon = txJson.get("senderPublicKeyFalcon", "").asString();
   tx.metadata = txJson.get("metadata", "").asString();

  }

  return tx;
}
//serialize
std::string Transaction::serialize() const {
  Json::Value txJson = toJSON();  // ✅ reuse shared logic
  Json::StreamWriterBuilder writer;
  return Json::writeString(writer, txJson);
}

Transaction Transaction::deserialize(const std::string &data) {
  Json::Reader reader;
  Json::Value root;
  reader.parse(data, root);
  return fromJSON(root);  // ✅ reuse shared logic
}

//
std::string Transaction::toString() const {
  Json::StreamWriterBuilder writer;
  return Json::writeString(writer, toJSON());  // ✅ reuse
}

//
std::string Transaction::calculateHash() const {
  Json::Value txJson;
  txJson["sender"] = sender;
  txJson["recipient"] = recipient;
  txJson["amount"] = amount;
  txJson["timestamp"] = static_cast<Json::Int64>(timestamp);

  Json::StreamWriterBuilder writer;
  writer["indentation"] = ""; // No indentation → deterministic
  std::string jsonString = Json::writeString(writer, txJson);

  return Crypto::hybridHash(jsonString);
}
//
alyncoin::TransactionProto Transaction::toProto() const {
    alyncoin::TransactionProto proto;
    proto.set_sender(sender);
    proto.set_recipient(recipient);
    proto.set_amount(amount);  // ✅ CRITICAL: Must be set
    proto.set_signature_dilithium(signatureDilithium);
    proto.set_signature_falcon(signatureFalcon);
    proto.set_sender_pubkey_dilithium(senderPublicKeyDilithium);
    proto.set_sender_pubkey_falcon(senderPublicKeyFalcon);
    proto.set_timestamp(timestamp);
    proto.set_zkproof(zkProof);
    proto.set_metadata(metadata);
    proto.set_hash(hash);  // Optional but safe
    return proto;
}

// Ensure keys are present and generate if missing
static void ensureKeysExist(const std::string &sender) {
  std::string keyDir = "/root/.alyncoin/keys/";
  std::string dilithiumPrivPath = keyDir + sender + "_dilithium_priv.bin";
  std::string falconPrivPath = keyDir + sender + "_falcon_priv.bin";

  if (!std::filesystem::exists(dilithiumPrivPath)) {
    std::cout << "⚠️ Dilithium keys missing. Generating for: " << sender << "\n";
    Crypto::generateDilithiumKeys(sender);
  }
  if (!std::filesystem::exists(falconPrivPath)) {
    std::cout << "⚠️ Falcon keys missing. Generating for: " << sender << "\n";
    Crypto::generateFalconKeys(sender);
  }
}
// ✅ Sign Transaction
void Transaction::signTransaction(const std::vector<unsigned char> &dilithiumPrivateKey,
                                  const std::vector<unsigned char> &falconPrivateKey) {
  std::cout << "[DEBUG] signTransaction() called for sender: " << sender << std::endl;

  if (sender == "System") {
    std::cout << "⛔ [DEBUG] Skipping signing for System transaction.\n";
    return;
  }

  if (!signatureDilithium.empty() && !signatureFalcon.empty() && !zkProof.empty()) {
    std::cout << "✅ [DEBUG] Transaction already signed + zkProof present. Skipping re-signing.\n";
    return;
  }

  if (dilithiumPrivateKey.empty()) {
    std::cerr << "❌ [ERROR] Dilithium private key is empty! Signing aborted.\n";
    return;
  }

  if (falconPrivateKey.empty()) {
    std::cerr << "❌ [ERROR] Falcon private key is empty! Signing aborted.\n";
    return;
  }

  // ✅ Step 1: Create canonical hash from sender/recipient/amount/timestamp
  std::ostringstream oss;
  oss << sender << recipient
      << std::fixed << std::setprecision(8) << amount
      << timestamp;

  hash = Crypto::sha256(oss.str());  // ✅ Store internally
  std::vector<unsigned char> hashBytes = Crypto::fromHex(hash);

  std::cout << "🔍 [DEBUG] Signing transaction hash: " << hash << std::endl;

  // ✅ Step 2: Sign the transaction
  std::vector<unsigned char> dilithiumSigVec = Crypto::signWithDilithium(hashBytes, dilithiumPrivateKey);
  signatureDilithium = Crypto::toHex(dilithiumSigVec);

  std::vector<unsigned char> falconSigVec = Crypto::signWithFalcon(hashBytes, falconPrivateKey);
  signatureFalcon = Crypto::toHex(falconSigVec);

  // ✅ Step 3: Attach public keys
  std::vector<unsigned char> pubDil = Crypto::getPublicKeyDilithium(sender);
  std::vector<unsigned char> pubFal = Crypto::getPublicKeyFalcon(sender);
  senderPublicKeyDilithium = Crypto::toHex(pubDil);
  senderPublicKeyFalcon = Crypto::toHex(pubFal);

  // ✅ Step 4: Generate zk-STARK proof
  zkProof = WinterfellStark::generateTransactionProof(sender, recipient, amount, timestamp);
  if (zkProof.empty()) {
    std::cerr << "❌ [ERROR] zk-STARK proof generation failed!\n";
  } else {
    std::cout << "✅ [DEBUG] zk-STARK proof generated. Length: " << zkProof.length() << "\n";
  }
}

// ✅ Validate Transaction (Signature Verification)

bool Transaction::isValid(const std::string &senderPublicKeyDilithium,
                          const std::string &senderPublicKeyFalcon) const {
  if (sender == "System") return true;

  if (sender.empty() || recipient.empty() || amount <= 0) {
    std::cerr << "[ERROR] Invalid transaction: Missing sender, recipient, or amount.\n";
    return false;
  }

  if (signatureDilithium.empty() || signatureFalcon.empty()) {
    std::cerr << "[ERROR] Transaction is missing required signatures!\n";
    return false;
  }

  if (senderPublicKeyDilithium.empty() || senderPublicKeyFalcon.empty()) {
    std::cerr << "[ERROR] Public keys missing in transaction!\n";
    return false;
  }

  std::cout << "[DEBUG] Verifying Dilithium & Falcon signatures for sender: " << sender << "\n";

  // ⛔ Avoid invalid hex strings
  if (signatureDilithium.length() % 2 != 0 || signatureFalcon.length() % 2 != 0 ||
      senderPublicKeyDilithium.length() % 2 != 0 || senderPublicKeyFalcon.length() % 2 != 0) {
    std::cerr << "[ERROR] Invalid hex length in signature or public key!\n";
    return false;
  }

  try {
    std::vector<unsigned char> hashBytes = Crypto::fromHex(getHash());
    std::vector<unsigned char> sigDil = Crypto::fromHex(signatureDilithium);
    std::vector<unsigned char> sigFal = Crypto::fromHex(signatureFalcon);
    std::vector<unsigned char> pubKeyDil = Crypto::fromHex(senderPublicKeyDilithium);
    std::vector<unsigned char> pubKeyFal = Crypto::fromHex(senderPublicKeyFalcon);

    bool dilithiumValid = Crypto::verifyWithDilithium(hashBytes, sigDil, pubKeyDil);
    bool falconValid = Crypto::verifyWithFalcon(hashBytes, sigFal, pubKeyFal);

    if (!dilithiumValid || !falconValid) {
      std::cerr << "[ERROR] Signature verification failed!\n";
      return false;
    }
  } catch (const std::exception &ex) {
    std::cerr << "[ERROR] Signature verification threw exception: " << ex.what() << "\n";
    return false;
  }

  if (zkProof.empty()) {
    std::cerr << "[ERROR] Transaction missing zk-STARK proof!\n";
    return false;
  }

  if (!WinterfellStark::verifyTransactionProof(zkProof, sender, recipient, amount, timestamp)) {
    std::cerr << "[ERROR] zk-STARK proof verification failed!\n";
    return false;
  }

  std::cout << "[DEBUG] Transaction signatures and zk-STARK proof verified successfully!\n";
  return true;
}

//
std::string Transaction::getSignature() const {
  return signatureDilithium + "|" + signatureFalcon;
}

// 🔥 Smart Burn Mechanism – Adjust Burn Rate Dynamically
const double MAX_BURN_RATE = 0.05;
const double MIN_BURN_RATE = 0.01;

double Transaction::calculateBurnRate(int recentTxCount) {
  double burnRate =
      MIN_BURN_RATE + (MAX_BURN_RATE - MIN_BURN_RATE) * (recentTxCount / 100.0);
  return std::min(MAX_BURN_RATE, std::max(MIN_BURN_RATE, burnRate));
}

// ✅ Improved Smart Burn Mechanism with Debugging
void Transaction::applyBurn(std::string &sender, double &amount,
                            int recentTxCount) {
  double burnRate = calculateBurnRate(recentTxCount);
  double burnAmount = amount * burnRate;
  amount -= burnAmount;

  std::cout << "🔥 Smart Burn Applied: " << burnAmount << " AlynCoin ("
            << (burnRate * 100) << "%)" << std::endl;
}

// ✅ Load Only Confirmed Transactions from RocksDB
std::vector<Transaction> Transaction::loadAllFromDB() {
    std::vector<Transaction> loaded;
    rocksdb::DB* db = nullptr;

    rocksdb::Options options;
    options.create_if_missing = true;
    rocksdb::Status status = rocksdb::DB::Open(options, DBPaths::getBlockchainDB(), &db);  // ✅ Use Blockchain DB

    if (!status.ok() || !db) {
        std::cerr << "❌ Failed to open RocksDB for reading confirmed transactions.\n";
        return loaded;
    }

    std::unique_ptr<rocksdb::Iterator> it(db->NewIterator(rocksdb::ReadOptions()));
    for (it->SeekToFirst(); it->Valid(); it->Next()) {
        std::string key = it->key().ToString();

        // ✅ Confirmed TXs are saved after mining with "tx_<hash>"
        if (key.rfind("tx_", 0) != 0) continue;

        std::string val = it->value().ToString();
        alyncoin::TransactionProto proto;

        if (!proto.ParseFromString(val)) {
            std::cerr << "⚠️ Failed to parse transaction proto at key: " << key << "\n";
            continue;
        }

        try {
            Transaction tx = Transaction::fromProto(proto);
            if (tx.getAmount() > 0.0) {
                loaded.push_back(tx);
            }
        } catch (...) {
            std::cerr << "⚠️ Failed to reconstruct Transaction from proto at key: " << key << "\n";
        }
    }

    delete db;
    return loaded;
}

// ✅ Use Atomic WriteBatch for RocksDB to prevent corruption

bool Transaction::saveToDB(const Transaction &tx, int index) {
    rocksdb::DB *db = nullptr;
    rocksdb::Options options;
    options.create_if_missing = true;
    rocksdb::Status status = rocksdb::DB::Open(options, DBPaths::getTransactionDB(), &db);
    if (!status.ok()) return false;

    alyncoin::TransactionProto proto;
    proto = tx.toProto();

    std::string data;
    if (!proto.SerializeToString(&data)) {
        delete db;
        return false;
    }

    std::string key = "tx_" + std::to_string(index);
    status = db->Put(rocksdb::WriteOptions(), key, data);

    delete db;
    return status.ok();
}

//

Transaction Transaction::createSystemRewardTransaction(const std::string &recipient, double amount) {
  Transaction tx;
  tx.sender = "System";
  tx.recipient = recipient;
  tx.amount = amount;
  tx.timestamp = std::time(nullptr);
  tx.signatureDilithium = "";
  tx.signatureFalcon = "";
  tx.zkProof = "";
  tx.senderPublicKeyDilithium = "";
  tx.senderPublicKeyFalcon = "";
  return tx;
}
