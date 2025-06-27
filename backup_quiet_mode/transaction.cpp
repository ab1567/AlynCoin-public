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
#include "crypto_utils.h"
#include "logging_utils.h"

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
    return hash.empty() ? getTransactionHash() : hash;
}

// ✅ Protobuf Serialization - Ensure all required fields are set
void Transaction::serializeToProtobuf(alyncoin::TransactionProto &proto) const {
    proto.set_sender(sender);
    proto.set_recipient(recipient);
    proto.set_amount(amount);

    if (!signatureDilithium.empty())
        proto.set_signature_dilithium(Crypto::toHex(std::vector<unsigned char>(signatureDilithium.begin(), signatureDilithium.end())));

    if (!signatureFalcon.empty())
        proto.set_signature_falcon(Crypto::toHex(std::vector<unsigned char>(signatureFalcon.begin(), signatureFalcon.end())));

    if (!senderPublicKeyDilithium.empty())
        proto.set_sender_pubkey_dilithium(Crypto::toHex(std::vector<unsigned char>(senderPublicKeyDilithium.begin(), senderPublicKeyDilithium.end())));

    if (!senderPublicKeyFalcon.empty())
        proto.set_sender_pubkey_falcon(Crypto::toHex(std::vector<unsigned char>(senderPublicKeyFalcon.begin(), senderPublicKeyFalcon.end())));

    proto.set_timestamp(timestamp);
    proto.set_metadata(metadata);
    proto.set_zkproof(zkProof);
    proto.set_hash(hash);
}

bool Transaction::deserializeFromProtobuf(const alyncoin::TransactionProto &proto) {
    sender = proto.sender();
    recipient = proto.recipient();
    amount = proto.amount();

    std::vector<unsigned char> sigDil = Crypto::fromHex(proto.signature_dilithium());
    if (!sigDil.empty()) {
        signatureDilithium = std::string(sigDil.begin(), sigDil.end());
    } else {
quietPrint( "❌ [ERROR] signature_dilithium is empty!" << std::endl);
    }

    std::vector<unsigned char> sigFal = Crypto::fromHex(proto.signature_falcon());
    if (!sigFal.empty()) {
        signatureFalcon = std::string(sigFal.begin(), sigFal.end());
    } else {
quietPrint( "❌ [ERROR] signature_falcon is empty!" << std::endl);
    }

    std::string pkDil = proto.sender_pubkey_dilithium();
    if (!pkDil.empty()) {
        if (pkDil.size() == DILITHIUM_PUBLIC_KEY_BYTES) {
            senderPublicKeyDilithium = pkDil;
        } else {
quietPrint( "⚠️ [ERROR] sender_pubkey_dilithium wrong length: " << pkDil.size() << std::endl);
        }
    } else {
quietPrint( "❌ [ERROR] sender_pubkey_dilithium is empty!" << std::endl);
    }

    std::string pkFal = proto.sender_pubkey_falcon();
    if (!pkFal.empty()) {
        if (pkFal.size() == FALCON_PUBLIC_KEY_BYTES) {
            senderPublicKeyFalcon = pkFal;
        } else {
quietPrint( "⚠️ [ERROR] sender_pubkey_falcon wrong length: " << pkFal.size() << std::endl);
        }
    } else {
quietPrint( "❌ [ERROR] sender_pubkey_falcon is empty!" << std::endl);
    }

    timestamp = proto.timestamp();
    metadata = proto.metadata();
    zkProof = proto.zkproof();
    hash = proto.hash();

    if (hash.empty()) {
        hash = getTransactionHash();
    }

    return true;
}

// ✅ Transaction::fromProto - hex decode required fields
Transaction Transaction::fromProto(const alyncoin::TransactionProto &proto) {
    auto safeStr = [](const std::string &val, const std::string &label, size_t maxLen = 10000) -> std::string {
        if (val.size() > maxLen) {
            std::cerr << "❌ [Transaction::fromProto] " << label << " too long (" << val.size() << " bytes)." << std::endl;
            return "";
        }
        return val;
    };

    std::string sender        = safeStr(proto.sender(), "sender", 4096);
    std::string recipient     = safeStr(proto.recipient(), "recipient", 4096);
    std::string sigDilHex     = safeStr(proto.signature_dilithium(), "signature_dilithium", 10000);
    std::string sigFalHex     = safeStr(proto.signature_falcon(), "signature_falcon", 10000);
    std::string zkProof       = safeStr(proto.zkproof(), "zkproof", 50000);
    std::string metadata      = safeStr(proto.metadata(), "metadata", 16384);
    std::string txHash        = safeStr(proto.hash(), "hash", 1024);
    std::string dilPKHex      = safeStr(proto.sender_pubkey_dilithium(), "sender_pubkey_dilithium", 10000);
    std::string falPKHex      = safeStr(proto.sender_pubkey_falcon(), "sender_pubkey_falcon", 10000);

    Transaction tx(sender, recipient, proto.amount(), sigDilHex, sigFalHex, proto.timestamp());

    tx.setZkProof(zkProof);
    tx.metadata = metadata;

    tx.senderPublicKeyDilithium = dilPKHex.empty() ? "" : dilPKHex;
    tx.senderPublicKeyFalcon    = falPKHex.empty() ? "" : falPKHex;

    tx.hash = txHash.empty() ? tx.getTransactionHash() : txHash;

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
  tx["timestamp"] = static_cast<Json::Int64>(timestamp);
  tx["metadata"] = metadata;

  // ✅ Encode binary data to base64
  tx["signatureDilithium"] = Crypto::base64Encode(signatureDilithium);
  tx["signatureFalcon"] = Crypto::base64Encode(signatureFalcon);
  tx["zkProof"] = Crypto::base64Encode(zkProof);
  tx["senderPublicKeyDilithium"] = Crypto::base64Encode(senderPublicKeyDilithium);
  tx["senderPublicKeyFalcon"] = Crypto::base64Encode(senderPublicKeyFalcon);

  return tx;
}

// From JSON
Transaction Transaction::fromJSON(const Json::Value &txJson) {
  Transaction tx;
  tx.sender = txJson.get("sender", "").asString();
  tx.recipient = txJson.get("recipient", "").asString();
  tx.amount = txJson.get("amount", 0.0).asDouble();
  tx.timestamp = txJson.get("timestamp", 0).asInt64();
  tx.metadata = txJson.get("metadata", "").asString();

  if (tx.sender != "System") {
    // ✅ Decode base64-encoded binary fields
    tx.signatureDilithium = Crypto::base64Decode(txJson.get("signatureDilithium", "").asString());
    tx.signatureFalcon = Crypto::base64Decode(txJson.get("signatureFalcon", "").asString());
    tx.zkProof = Crypto::base64Decode(txJson.get("zkProof", "").asString());
    tx.senderPublicKeyDilithium = Crypto::base64Decode(txJson.get("senderPublicKeyDilithium", "").asString());
    tx.senderPublicKeyFalcon = Crypto::base64Decode(txJson.get("senderPublicKeyFalcon", "").asString());
  }

  if (tx.hash.empty()) {
    tx.hash = tx.getTransactionHash();
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
    proto.set_signature_dilithium(Crypto::toHex(std::vector<unsigned char>(signatureDilithium.begin(), signatureDilithium.end())));
    proto.set_signature_falcon(Crypto::toHex(std::vector<unsigned char>(signatureFalcon.begin(), signatureFalcon.end())));
    proto.set_sender_pubkey_dilithium(Crypto::toHex(std::vector<unsigned char>(senderPublicKeyDilithium.begin(), senderPublicKeyDilithium.end())));
    proto.set_sender_pubkey_falcon(Crypto::toHex(std::vector<unsigned char>(senderPublicKeyFalcon.begin(), senderPublicKeyFalcon.end())));
    proto.set_timestamp(timestamp);
    proto.set_zkproof(zkProof);
    proto.set_metadata(metadata);
    proto.set_hash(hash);  // Optional but safe
    return proto;
}

// ✅ Sign Transaction
void Transaction::signTransaction(const std::vector<unsigned char> &dilithiumPrivateKey,
                                   const std::vector<unsigned char> &falconPrivateKey) {
debugPrint( "[DEBUG] signTransaction() called for sender: " << sender << std::endl);

    if (sender == "System") {
quietPrint( "⛔ [DEBUG] Skipping signing for System transaction.\n");
        return;
    }

    if (!signatureDilithium.empty() && !signatureFalcon.empty() && !zkProof.empty()) {
debugPrint( "✅ [DEBUG] Transaction already signed + zkProof present. Skipping re-signing.\n");
        return;
    }

    if (dilithiumPrivateKey.empty()) {
quietPrint( "❌ [ERROR] Dilithium private key is empty! Signing aborted.\n");
        return;
    }

    if (falconPrivateKey.empty()) {
quietPrint( "❌ [ERROR] Falcon private key is empty! Signing aborted.\n");
        return;
    }

    // ✅ Step 1: Create canonical hash from sender/recipient/amount/timestamp
   hash = getTransactionHash();
    std::vector<unsigned char> hashBytes = Crypto::fromHex(hash);

quietPrint( "🔍 [DEBUG] Signing transaction hash: " << hash << std::endl);

    // ✅ Step 2: Sign the transaction
    std::vector<unsigned char> dilithiumSigVec = Crypto::signWithDilithium(hashBytes, dilithiumPrivateKey);
    signatureDilithium = Crypto::toHex(dilithiumSigVec);

    std::vector<unsigned char> falconSigVec = Crypto::signWithFalcon(hashBytes, falconPrivateKey);
    signatureFalcon = Crypto::toHex(falconSigVec);

    // ✅ Step 3: Attach public keys as hex
    std::vector<unsigned char> pubDil = Crypto::getPublicKeyDilithium(sender);
    std::vector<unsigned char> pubFal = Crypto::getPublicKeyFalcon(sender);
    senderPublicKeyDilithium = Crypto::toHex(pubDil);
    senderPublicKeyFalcon = Crypto::toHex(pubFal);

    // ✅ Step 4: Generate zk-STARK proof
    zkProof = WinterfellStark::generateTransactionProof(sender, recipient, amount, timestamp);
    if (zkProof.empty()) {
quietPrint( "❌ [ERROR] zk-STARK proof generation failed!\n");
    } else {
quietPrint( "✅ [DEBUG] zk-STARK proof generated. Length: " << zkProof.length() << "\n");
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

  try {
    std::vector<unsigned char> hashBytes = Crypto::fromHex(getHash());
    std::vector<unsigned char> sigDil = Crypto::fromHex(signatureDilithium);
    std::vector<unsigned char> sigFal = Crypto::fromHex(signatureFalcon);
    std::vector<unsigned char> pubKeyDil = Crypto::fromHex(senderPublicKeyDilithium);
    std::vector<unsigned char> pubKeyFal = Crypto::fromHex(senderPublicKeyFalcon);

quietPrint( "[DEBUG] Verifying Dilithium & Falcon signatures for sender: " << sender << "\n");
debugPrint( "[DEBUG] Hash used for signature: " << getHash() << "\n");

    if (!Crypto::verifyWithDilithium(hashBytes, sigDil, pubKeyDil)) {
      std::cerr << "[ERROR] Dilithium signature verification failed!\n";
      return false;
    }

    if (!Crypto::verifyWithFalcon(hashBytes, sigFal, pubKeyFal)) {
      std::cerr << "[ERROR] Falcon signature verification failed!\n";
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

quietPrint( "[DEBUG] Verifying zk-STARK transaction proof... length = " << zkProof.size() << " bytes\n");

  if (!WinterfellStark::verifyTransactionProof(zkProof, sender, recipient, amount, timestamp)) {
    std::cerr << "[ERROR] zk-STARK proof verification failed!\n";
    return false;
  }

debugPrint( "[DEBUG] Transaction signatures and zk-STARK proof verified successfully!\n");
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
    rocksdb::DB* rawDB = nullptr;

    rocksdb::Options options;
    options.create_if_missing = true;

    rocksdb::Status status = rocksdb::DB::OpenForReadOnly(
        options, DBPaths::getBlockchainDB(), &rawDB);

    if (!status.ok() || !rawDB) {
quietPrint( "❌ Failed to open RocksDB for reading confirmed transactions.\n");
        return loaded;
    }

    std::unique_ptr<rocksdb::DB> db(rawDB);  // ✅ wrap in smart pointer
    std::unique_ptr<rocksdb::Iterator> it(db->NewIterator(rocksdb::ReadOptions()));

    for (it->SeekToFirst(); it->Valid(); it->Next()) {
        std::string key = it->key().ToString();

        if (key.rfind("tx_", 0) != 0) continue;

        std::string val = it->value().ToString();
        alyncoin::TransactionProto proto;

        if (!proto.ParseFromString(val)) {
quietPrint( "⚠️ Failed to parse transaction proto at key: " << key << "\n");
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

    return loaded;  // ✅ db auto-cleaned by smart pointer
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
  tx.hash = tx.getTransactionHash();
  return tx;
}
