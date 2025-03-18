#include <iostream>
#include <sstream>
#include <fstream>  // ✅ Fix: Ensure file handling works properly
#include "transaction.h"
#include "hash.h"
#include "crypto_utils.h"
#include <algorithm>
#include <iomanip>
#include <thread>
#include <openssl/sha.h>
#include <chrono>
#include <filesystem>
#include <rocksdb/db.h>
#include "generated/transaction_protos.pb.h"
#include "base64.h"

namespace fs = std::filesystem;

Transaction::Transaction() : sender(""), recipient(""), amount(0), signature(""), timestamp(std::time(nullptr)) {}

Transaction::Transaction(const std::string& sender, const std::string& recipient, double amount, const std::string& signature)
    : sender(sender), recipient(recipient), amount(amount), signature(signature), timestamp(std::time(nullptr)) {
}

std::string Transaction::getSender() const { return sender; }
std::string Transaction::getRecipient() const { return recipient; }
double Transaction::getAmount() const { return amount; }
std::string Transaction::getSignature() const { return signature; }
//
std::string Transaction::getTransactionHash() const {
    std::ostringstream data;
    data << sender << recipient << amount << timestamp;  // ✅ Ensure timestamp is included
    return Crypto::keccak256(data.str());  // ✅ Ensure consistent hashing
}
//
time_t Transaction::getTimestamp() const {
    return timestamp;
}

//
Transaction Transaction::fromProto(const alyncoin::TransactionProto& proto) {
    return Transaction(proto.sender(), proto.recipient(), proto.amount(), proto.signature());
}

//
std::string Transaction::getHash() const {
    std::ostringstream ss;
    ss << sender << recipient << amount << signature << timestamp;  // ✅ Added timestamp
    return Crypto::keccak256(ss.str());
}

// ✅ Protobuf Serialization - Ensure all required fields are set
void Transaction::serializeToProtobuf(alyncoin::TransactionProto& proto) const {
    if (sender.empty() || recipient.empty() || amount <= 0 || signature.empty()) {
        std::cerr << "❌ [ERROR] Attempted to serialize an invalid transaction!" << std::endl;
        return;
    }

    proto.set_sender(sender);
    proto.set_recipient(recipient);
    proto.set_amount(amount);
    proto.set_signature(signature);
    proto.set_timestamp(timestamp);
}

// ✅ Protobuf Deserialization - Use safer checks
bool Transaction::deserializeFromProtobuf(const alyncoin::TransactionProto& proto) {
    if (proto.sender().empty() || proto.recipient().empty() || proto.signature().empty()) {
        std::cerr << "❌ [ERROR] Transaction protobuf missing required fields!" << std::endl;
        return false;
    }

    sender = proto.sender();
    recipient = proto.recipient();
    amount = proto.has_amount() ? proto.amount() : 0;  // ✅ Use `has_*()` if fields are optional
    signature = proto.signature();
    timestamp = proto.has_timestamp() ? proto.timestamp() : std::time(nullptr); // ✅ Use default timestamp

    return true;
}
//
std::string Transaction::serialize() const {
    Json::Value txJson;
    txJson["sender"] = sender;
    txJson["recipient"] = recipient;
    txJson["amount"] = amount;
    txJson["signature"] = signature;
    txJson["timestamp"] = timestamp;

    Json::StreamWriterBuilder writer;
    return Json::writeString(writer, txJson);
}
//
Transaction Transaction::deserialize(const std::string& data) {
    Json::Reader reader;
    Json::Value root;
    reader.parse(data, root);

    Transaction tx(
        root["sender"].asString(),
        root["recipient"].asString(),
        root["amount"].asDouble(),
        root["signature"].asString()
    );
    tx.timestamp = root["timestamp"].asUInt64();
    return tx;
}

// ✅ Convert Transaction to JSON using Protobuf
Json::Value Transaction::toJSON() const {
    Json::Value tx;
    tx["sender"] = sender;
    tx["recipient"] = recipient;
    tx["amount"] = amount;
    tx["signature"] = signature;
    tx["timestamp"] = static_cast<Json::Int64>(timestamp);
    return tx;
}

// ✅ Convert JSON to Transaction using Protobuf Parsing
Transaction Transaction::fromJSON(const Json::Value& txJson) {
    if (!txJson.isMember("sender") || !txJson.isMember("recipient") ||
        !txJson.isMember("amount") || !txJson.isMember("signature") || !txJson.isMember("timestamp")) {
        std::cerr << "❌ [ERROR] Missing fields in transaction JSON!\n";
        throw std::runtime_error("Invalid transaction JSON structure.");
    }

    Transaction tx;
    tx.sender = txJson["sender"].asString();
    tx.recipient = txJson["recipient"].asString();
    tx.amount = txJson["amount"].asDouble();
    tx.signature = txJson["signature"].asString();
    tx.timestamp = txJson["timestamp"].asInt64();  // ✅ Ensure timestamp is parsed

    return tx;
}

// src/transaction.cpp
std::string Transaction::toString() const {
    Json::Value txJson;
    txJson["sender"] = sender;
    txJson["recipient"] = recipient;
    txJson["amount"] = amount;
    txJson["signature"] = signature;
    txJson["timestamp"] = static_cast<Json::Int64>(timestamp);  // ✅ Ensure timestamp is included

    Json::StreamWriterBuilder writer;
    return Json::writeString(writer, txJson); // ✅ Convert Transaction to JSON string
}

//
std::string Transaction::calculateHash() const {
    std::ostringstream ss;
    ss << sender << recipient << amount << timestamp;
    return Crypto::keccak256(ss.str());
}

// ✅ Sign Transaction
void Transaction::signTransaction(const std::string& privateKeyPath, bool useManualSignature) {
    if (!signature.empty()) {
        std::cout << "✅ [DEBUG] Transaction already signed. Skipping re-signing.\n";
        return;
    }

    std::ifstream keyFile(privateKeyPath);
    if (!keyFile.is_open()) {
        std::cerr << "❌ [ERROR] Private key file not found: " << privateKeyPath << std::endl;
        return;
    }

    std::stringstream buffer;
    buffer << keyFile.rdbuf();
    std::string privateKey = buffer.str();
    keyFile.close();

    if (privateKey.empty()) {
        std::cerr << "❌ [ERROR] Private key is empty! Signing aborted.\n";
        return;
    }

    std::string transactionHash = getTransactionHash();
    std::cout << "🔍 [DEBUG] Signing transaction hash: " << transactionHash << std::endl;

    signature = Crypto::signMessage(transactionHash, privateKey, false);

    if (signature.empty()) {
        std::cerr << "❌ [ERROR] Transaction signing failed!\n";
    } else {
        std::cout << "✅ [DEBUG] Transaction signed successfully!\n";
    }
}

// ✅ Validate Transaction (Signature Verification)
bool Transaction::isValid(const std::string& dummyPath) const {
    if (sender.empty() || recipient.empty() || amount <= 0) {
        std::cerr << "❌ [ERROR] Invalid transaction: Missing sender, recipient, or amount.\n";
        return false;
    }

    if (signature.empty()) {
        std::cerr << "❌ [ERROR] Transaction is missing a signature!\n";
        return false;
    }

    std::string cleanSender = sender;
    std::replace(cleanSender.begin(), cleanSender.end(), ' ', '_');  // Handle spaces properly
    std::string senderPublicKeyPath = "/root/.alyncoin/keys/" + cleanSender + "_public.pem";

    if (!fs::exists(senderPublicKeyPath)) {
        std::cerr << "⚠️ [WARNING] Public key missing for " << cleanSender << "! Generating now...\n";
        Crypto::generateKeysForUser(cleanSender);
    }

    std::cout << "🔍 [DEBUG] Verifying transaction signature for sender: " << sender << "\n";
    std::cout << "[DEBUG] Public key path used: " << senderPublicKeyPath << "\n";

    bool verification = Crypto::verifyMessage(senderPublicKeyPath, signature, getTransactionHash());

    if (!verification) {
        std::cerr << "❌ [ERROR] Signature verification failed for transaction!\n";
        return false;
    }

    std::cout << "✅ [DEBUG] Transaction signature verified successfully!\n";
    return true;
}

// 🔥 Smart Burn Mechanism – Adjust Burn Rate Dynamically
const double MAX_BURN_RATE = 0.05;
const double MIN_BURN_RATE = 0.01;

double Transaction::calculateBurnRate(int recentTxCount) {
    double burnRate = MIN_BURN_RATE + (MAX_BURN_RATE - MIN_BURN_RATE) * (recentTxCount / 100.0);
    return std::min(MAX_BURN_RATE, std::max(MIN_BURN_RATE, burnRate));
}

// ✅ Improved Smart Burn Mechanism with Debugging
void Transaction::applyBurn(std::string& sender, double& amount, int recentTxCount) {
    double burnRate = calculateBurnRate(recentTxCount);
    double burnAmount = amount * burnRate;
    amount -= burnAmount;

    std::cout << "🔥 Smart Burn Applied: " << burnAmount << " AlynCoin (" << (burnRate * 100) << "%)" << std::endl;
}

// ✅ Load Transactions from RocksDB with Error Handling
std::vector<Transaction> Transaction::loadFromDB() {
    std::vector<Transaction> transactions;
    rocksdb::DB* db;
    rocksdb::Options options;
    options.create_if_missing = true;

    rocksdb::Status status = rocksdb::DB::Open(options, "data/transactions_db", &db);
    if (!status.ok()) {
        std::cerr << "❌ [ERROR] Failed to open transaction database!" << std::endl;
        return transactions;
    }

    rocksdb::Iterator* it = db->NewIterator(rocksdb::ReadOptions());
    for (it->SeekToFirst(); it->Valid(); it->Next()) {
        alyncoin::TransactionProto txProto;
        if (!txProto.ParseFromString(it->value().ToString())) {
            std::cerr << "❌ [ERROR] Corrupt transaction data found in DB!" << std::endl;
            continue; // Skip corrupted entries
        }
        transactions.push_back(Transaction::fromProto(txProto));
    }

    delete it;
    delete db;
    return transactions;
}
// ✅ Use Atomic WriteBatch for RocksDB to prevent corruption
bool Transaction::saveToDB(const Transaction& tx, int index) {
    rocksdb::DB* db;
    rocksdb::Options options;
    options.create_if_missing = true;
    
    rocksdb::Status status = rocksdb::DB::Open(options, "data/transactions_db", &db);
    if (!status.ok()) {
        std::cerr << "❌ [ERROR] Failed to open transaction database!" << std::endl;
        return false;
    }

    rocksdb::WriteBatch batch;
    Json::StreamWriterBuilder writer;
    std::string txData = Json::writeString(writer, tx.toJSON());

    batch.Put("tx_" + std::to_string(index), txData);
    status = db->Write(rocksdb::WriteOptions(), &batch);

    delete db;
    return status.ok();
}
