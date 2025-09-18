#include <generated/transaction_protos.pb.h>
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

// ✅ Constructor:
Transaction::Transaction()
    : sender(""), recipient(""), amount(0), signatureDilithium(""),
      signatureFalcon(""), timestamp(std::time(nullptr)), nonce(0) {}

Transaction::Transaction(const std::string &sender,
                         const std::string &recipient, double amount,
                         const std::string &signatureDilithium,
                         const std::string &signatureFalcon,
                         std::time_t timestamp, uint64_t nonce)
    : sender(sender), recipient(recipient), amount(amount),
      signatureDilithium(signatureDilithium), signatureFalcon(signatureFalcon),
      timestamp(timestamp), nonce(nonce) {}

// ✅ Getters:
std::string Transaction::getSender() const { return sender; }
std::string Transaction::getRecipient() const { return recipient; }
double Transaction::getAmount() const { return amount; }
std::string Transaction::getSignatureDilithium() const {
  return signatureDilithium;
}
std::string Transaction::getSignatureFalcon() const { return signatureFalcon; }
time_t Transaction::getTimestamp() const { return timestamp; }
uint64_t Transaction::getNonce() const { return nonce; }
std::string Transaction::getZkProof() const { return zkProof; }
void Transaction::setZkProof(const std::string &proof) { zkProof = proof; }
void Transaction::setNonce(uint64_t value) { nonce = value; }

// Transaction Hash:
inline std::string canonicalAmount(double amount) {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(8) << amount;
    return oss.str();
}

// 2. Transaction hash: canonicalize all fields for hash, including amount
std::string Transaction::getTransactionHash() const {
    std::ostringstream data;
    data << sender << recipient << canonicalAmount(amount) << timestamp << nonce;
    return Crypto::hybridHash(data.str());
}
//

std::string Transaction::getHash() const {
    return hash.empty() ? getTransactionHash() : hash;
}

// ✅ Protobuf Serialization - Ensure all required fields are set
// 3. When serializing to Protobuf, also save canonicalAmount as a string field
void Transaction::serializeToProtobuf(alyncoin::TransactionProto &proto) const {
    proto.set_sender(sender);
    proto.set_recipient(recipient);
    proto.set_amount(amount);

    // --- New: store canonicalAmount as string ---
    proto.set_amount_str(canonicalAmount(amount));

    if (!signatureDilithium.empty())
        proto.set_signature_dilithium(
            reinterpret_cast<const char*>(signatureDilithium.data()),
            signatureDilithium.size());

    if (!signatureFalcon.empty())
        proto.set_signature_falcon(
            reinterpret_cast<const char*>(signatureFalcon.data()),
            signatureFalcon.size());

    if (!senderPublicKeyDilithium.empty())
        proto.set_sender_pubkey_dilithium(
            reinterpret_cast<const char*>(senderPublicKeyDilithium.data()),
            senderPublicKeyDilithium.size());

    if (!senderPublicKeyFalcon.empty())
        proto.set_sender_pubkey_falcon(
            reinterpret_cast<const char*>(senderPublicKeyFalcon.data()),
            senderPublicKeyFalcon.size());

    proto.set_timestamp(timestamp);
    proto.set_nonce(nonce);

    // Clamp metadata safely
    if (metadata.size() > 16384) {
        std::cerr << "⚠️ [serializeToProtobuf] metadata too large (" << metadata.size() << " bytes). Truncating.\n";
        proto.set_metadata(metadata.substr(0, 16384));
    } else {
        proto.set_metadata(metadata);
    }

    proto.set_zkproof(zkProof);
    proto.set_hash(getTransactionHash()); // always recalculate canonical hash
}

// 4. Protobuf deserialization: always restore amount from both double and string
bool Transaction::deserializeFromProtobuf(const alyncoin::TransactionProto &proto) {
    try {
        sender = proto.sender();
        recipient = proto.recipient();
        amount = proto.amount();
        timestamp = proto.timestamp();
        nonce = proto.nonce();

        // Clamp metadata safely
        {
            std::string meta = proto.metadata();
            if (meta.size() > 16384) {
                std::cerr << "⚠️ [deserializeFromProtobuf] metadata too large (" << meta.size() << " bytes). Truncating.\n";
                meta.resize(16384);
            }
            metadata = meta;
        }

        zkProof = proto.zkproof();  // ✅ RAW binary (no fromHex)

        // --- New: always use amount_str if present for hash calculation
        std::string amount_str = !proto.amount_str().empty() ? proto.amount_str() : canonicalAmount(amount);

        hash = proto.hash();

        if (!proto.signature_dilithium().empty()) {
            const std::string& sig = proto.signature_dilithium();
            signatureDilithium.assign(sig.begin(), sig.end());
        } else {
            std::cerr << "⚠️ [deserializeFromProtobuf] Missing dilithium signature.\n";
        }

        if (!proto.signature_falcon().empty()) {
            const std::string& sig = proto.signature_falcon();
            signatureFalcon.assign(sig.begin(), sig.end());
        } else {
            std::cerr << "⚠️ [deserializeFromProtobuf] Missing falcon signature.\n";
        }

        if (!proto.sender_pubkey_dilithium().empty()) {
            const std::string &pkDil = proto.sender_pubkey_dilithium();
            if (pkDil.size() == DILITHIUM_PUBLIC_KEY_BYTES)
                senderPublicKeyDilithium.assign(pkDil.begin(), pkDil.end());
            else
                std::cerr << "⚠️ [deserializeFromProtobuf] Unexpected Dilithium key length: "
                          << pkDil.size() << "\n";
        } else {
            std::cerr << "⚠️ [deserializeFromProtobuf] Missing Dilithium pubkey.\n";
        }

        if (!proto.sender_pubkey_falcon().empty()) {
            const std::string &pkFal = proto.sender_pubkey_falcon();
            if (pkFal.size() == FALCON_PUBLIC_KEY_BYTES)
                senderPublicKeyFalcon.assign(pkFal.begin(), pkFal.end());
            else
                std::cerr << "⚠️ [deserializeFromProtobuf] Unexpected Falcon key length: "
                          << pkFal.size() << "\n";
        } else {
            std::cerr << "⚠️ [deserializeFromProtobuf] Missing Falcon pubkey.\n";
        }

        // --- Always recalc hash from canonical fields
        std::ostringstream data;
        data << sender << recipient << amount_str << timestamp << nonce;
        std::string canonical_hash = Crypto::hybridHash(data.str());
        if (hash.empty() || hash != canonical_hash) {
            std::cerr << "⚠️ [Transaction::deserializeFromProtobuf] Hash mismatch or empty! Recomputing canonical.\n";
            hash = canonical_hash;
        }

        return true;
    } catch (const std::exception &e) {
        std::cerr << "❌ [deserializeFromProtobuf] Exception: " << e.what() << "\n";
        return false;
    }
}
// ✅ Transaction fromProto()
Transaction Transaction::fromProto(const alyncoin::TransactionProto& protoTx) {
    Transaction tx;

    try {
        // String fields - safe access
        if (!protoTx.sender().empty()) {
            tx.sender = protoTx.sender();
        }
        if (!protoTx.recipient().empty()) {
            tx.recipient = protoTx.recipient();
        }
        if (!protoTx.metadata().empty()) {
            tx.metadata = protoTx.metadata();
        }
        if (!protoTx.hash().empty()) {
            tx.hash = protoTx.hash();
        }

        // Scalar fields
        tx.amount = protoTx.amount();
        tx.timestamp = protoTx.timestamp();
        tx.nonce = protoTx.nonce();

        // Critical field check
        if (tx.sender.empty() || tx.recipient.empty() || tx.amount <= 0.0) {
            std::cerr << "⚠️ [Transaction::fromProto] Missing critical field(s). Skipping.\n";
            return tx;
        }

        // 🚨 Direct assignment for raw binary fields
        if (!protoTx.signature_dilithium().empty()) {
            const std::string &sig = protoTx.signature_dilithium();
            if (sig.size() <= 10000) {
                tx.signatureDilithium.assign(sig.begin(), sig.end());
            } else {
                std::cerr << "⚠️ [Transaction::fromProto] Dilithium signature too large: "
                          << sig.size() << " bytes. Ignoring.\n";
            }
        }

        if (!protoTx.signature_falcon().empty()) {
            const std::string &sig = protoTx.signature_falcon();
            if (sig.size() <= 10000) {
                tx.signatureFalcon.assign(sig.begin(), sig.end());
            } else {
                std::cerr << "⚠️ [Transaction::fromProto] Falcon signature too large: "
                          << sig.size() << " bytes. Ignoring.\n";
            }
        }

        if (!protoTx.sender_pubkey_dilithium().empty()) {
            const std::string &pk = protoTx.sender_pubkey_dilithium();
            if (pk.size() <= 5000) {
                tx.senderPublicKeyDilithium.assign(pk.begin(), pk.end());
            } else {
                std::cerr << "⚠️ [Transaction::fromProto] Dilithium pubkey too large: "
                          << pk.size() << " bytes. Ignoring.\n";
            }
        }

        if (!protoTx.sender_pubkey_falcon().empty()) {
            const std::string &pk = protoTx.sender_pubkey_falcon();
            if (pk.size() <= 5000) {
                tx.senderPublicKeyFalcon.assign(pk.begin(), pk.end());
            } else {
                std::cerr << "⚠️ [Transaction::fromProto] Falcon pubkey too large: "
                          << pk.size() << " bytes. Ignoring.\n";
            }
        }
        if (!protoTx.zkproof().empty()) {
            tx.zkProof = protoTx.zkproof();  // raw binary
        }

        // Recompute hash if needed
        if (tx.hash.empty()) {
            tx.hash = tx.getTransactionHash();
        }
    } catch (const std::exception& ex) {
        std::cerr << "⚠️ [Transaction::fromProto] Exception: " << ex.what() << "\n";
    } catch (...) {
        std::cerr << "⚠️ [Transaction::fromProto] Unknown exception!\n";
    }

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
    tx["nonce"] = static_cast<Json::UInt64>(nonce);
    return tx;
  }

  tx["sender"] = sender;
  tx["recipient"] = recipient;
  tx["amount"] = amount;
  tx["timestamp"] = static_cast<Json::Int64>(timestamp);
  tx["nonce"] = static_cast<Json::UInt64>(nonce);
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
  tx.nonce = txJson.get("nonce", 0).asUInt64();
  tx.metadata = txJson.get("metadata", "").asString();

  if (tx.sender != "System") {
    // ✅ Decode base64-encoded binary fields with simple size guards
    auto decodeSafe = [](const std::string &b64, size_t limit, const std::string &field) {
      std::string decoded = Crypto::base64Decode(b64);
      if (decoded.size() > limit) {
        std::cerr << "⚠️ [Transaction::fromJSON] " << field << " too large: "
                  << decoded.size() << " bytes. Ignoring.\n";
        return std::string{};
      }
      return decoded;
    };

    tx.signatureDilithium = decodeSafe(txJson.get("signatureDilithium", "").asString(), 10000, "Dilithium signature");
    tx.signatureFalcon = decodeSafe(txJson.get("signatureFalcon", "").asString(), 10000, "Falcon signature");
    tx.zkProof = decodeSafe(txJson.get("zkProof", "").asString(), 10000, "zkProof");
    tx.senderPublicKeyDilithium = decodeSafe(txJson.get("senderPublicKeyDilithium", "").asString(), 5000, "Dilithium pubkey");
    tx.senderPublicKeyFalcon = decodeSafe(txJson.get("senderPublicKeyFalcon", "").asString(), 5000, "Falcon pubkey");
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
std::string Transaction::hashLegacy() const {
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
    proto.set_amount(amount);
    proto.set_timestamp(timestamp);
    proto.set_hash(hash);
    proto.set_nonce(nonce);

    if (sender == "System") {
        // Dev-fund or reward tx: skip keys/signatures
        if (metadata.size() > 16384) {
            std::cerr << "⚠️ [toProto] metadata too large (" << metadata.size() << " bytes). Truncating.\n";
            proto.set_metadata(metadata.substr(0, 16384));
        } else {
            proto.set_metadata(metadata);
        }
        return proto;
    }

    // 🚨 No hex! Store as raw binary:
    if (!signatureDilithium.empty()) {
        proto.set_signature_dilithium(signatureDilithium);
    }
    if (!signatureFalcon.empty()) {
        proto.set_signature_falcon(signatureFalcon);
    }
    if (!senderPublicKeyDilithium.empty()) {
        proto.set_sender_pubkey_dilithium(senderPublicKeyDilithium);
    }
    if (!senderPublicKeyFalcon.empty()) {
        proto.set_sender_pubkey_falcon(senderPublicKeyFalcon);
    }

    // zkProof is raw binary
    if (!zkProof.empty()) {
        proto.set_zkproof(zkProof);
    }

    if (metadata.size() > 16384) {
        std::cerr << "⚠️ [toProto] metadata too large (" << metadata.size() << " bytes). Truncating.\n";
        proto.set_metadata(metadata.substr(0, 16384));
    } else {
        proto.set_metadata(metadata);
    }

    return proto;
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
   hash = getTransactionHash();
    std::vector<unsigned char> hashBytes = Crypto::fromHex(hash);

    std::cout << "🔍 [DEBUG] Signing transaction hash: " << hash << std::endl;

    // ✅ Step 2: Sign the transaction
    std::vector<unsigned char> dilithiumSigVec = Crypto::signWithDilithium(hashBytes, dilithiumPrivateKey);
    signatureDilithium.assign(dilithiumSigVec.begin(), dilithiumSigVec.end());

    std::vector<unsigned char> falconSigVec = Crypto::signWithFalcon(hashBytes, falconPrivateKey);
    signatureFalcon.assign(falconSigVec.begin(), falconSigVec.end());

    // ✅ Step 3: Attach public keys (raw)
    if (senderPublicKeyDilithium.empty()) {
        std::vector<unsigned char> pubDil = Crypto::getPublicKeyDilithium(sender);
        senderPublicKeyDilithium.assign(pubDil.begin(), pubDil.end());
    }
    if (senderPublicKeyFalcon.empty()) {
        std::vector<unsigned char> pubFal = Crypto::getPublicKeyFalcon(sender);
        senderPublicKeyFalcon.assign(pubFal.begin(), pubFal.end());
    }

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

    if (signatureDilithium.length() > 10000 || signatureFalcon.length() > 10000) {
        std::cerr << "[ERROR] Signature too long: Dilithium(" << signatureDilithium.length()
                  << "), Falcon(" << signatureFalcon.length() << ")\n";
        return false;
    }

    if (senderPublicKeyDilithium.length() > 5000 || senderPublicKeyFalcon.length() > 5000) {
        std::cerr << "[ERROR] Public key too long: Dilithium(" << senderPublicKeyDilithium.length()
                  << "), Falcon(" << senderPublicKeyFalcon.length() << ")\n";
        return false;
    }

    std::vector<unsigned char> hashBytes;
    std::vector<unsigned char> sigDil, sigFal, pubKeyDil, pubKeyFal;

    try {
        hashBytes = Crypto::fromHex(getHash());
        sigDil.assign(signatureDilithium.begin(), signatureDilithium.end());
        sigFal.assign(signatureFalcon.begin(), signatureFalcon.end());
        pubKeyDil.assign(senderPublicKeyDilithium.begin(), senderPublicKeyDilithium.end());
        pubKeyFal.assign(senderPublicKeyFalcon.begin(), senderPublicKeyFalcon.end());
    } catch (const std::exception &ex) {
        std::cerr << "[ERROR] Decoding failed: " << ex.what() << "\n";
        return false;
    }

    std::cout << "[DEBUG] Verifying Dilithium & Falcon signatures for sender: " << sender << "\n";
    std::cout << "[DEBUG] Hash used for signature: " << getHash() << "\n";
    std::cout << "[DEBUG] Dilithium Sig Len: " << sigDil.size()
              << ", Falcon Sig Len: " << sigFal.size() << "\n";
    std::cout << "[DEBUG] Dilithium PubKey Len: " << pubKeyDil.size()
              << ", Falcon PubKey Len: " << pubKeyFal.size() << "\n";

    if (!Crypto::verifyWithDilithium(hashBytes, sigDil, pubKeyDil)) {
        std::cerr << "[ERROR] Dilithium signature verification failed!\n";
        return false;
    }

    if (!Crypto::verifyWithFalcon(hashBytes, sigFal, pubKeyFal)) {
        std::cerr << "[ERROR] Falcon signature verification failed!\n";
        return false;
    }

    // Address binding rule – always enforce
    {
        auto lower = [](std::string s){ std::transform(s.begin(), s.end(), s.begin(), ::tolower); return s; };
        const std::string sL = lower(sender);
        std::string expectedDil = Crypto::deriveAddressFromPub(pubKeyDil);
        std::string expectedFal = Crypto::deriveAddressFromPub(pubKeyFal);
        bool matches = (sL == expectedDil) || (sL == expectedFal);

        if (!matches) {
            std::cerr << "❌ ERR_ADDR_MISMATCH: sender=" << sender
                      << " expected(any)=[" << expectedDil << "," << expectedFal << "]\n";
            return false;
        }
    }

    // 💡 zk-STARK safety check
    if (zkProof.empty()) {
        std::cerr << "[ERROR] Transaction missing zk-STARK proof!\n";
        return false;
    }
    if (zkProof.size() > 5000) {
        std::cerr << "[ERROR] zk-STARK proof too long: " << zkProof.size() << "\n";
        return false;
    }

    std::cout << "[DEBUG] Verifying zk-STARK transaction proof... length = " << zkProof.size() << " bytes\n";

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

double Transaction::computeBurnedAmount(double amount, int recentTxCount) {
    return amount * calculateBurnRate(recentTxCount);
}

// ✅ Improved Smart Burn Mechanism with Debugging
void Transaction::applyBurn(std::string &sender, double &amount,
                            int recentTxCount) {
  double burnRate = calculateBurnRate(recentTxCount);
  double burnAmount = computeBurnedAmount(amount, recentTxCount);
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
        std::cerr << "❌ Failed to open RocksDB for reading confirmed transactions.\n";
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
Transaction Transaction::createSystemRewardTransaction(
    const std::string &recipient,
    double amount,
    time_t ts,
    const std::string &hashOverride) {

    Transaction tx;
    tx.sender = "System";
    tx.recipient = recipient;
    tx.amount = amount;
    tx.timestamp = ts;
    tx.signatureDilithium = "";
    tx.signatureFalcon = "";
    tx.zkProof = "";
    tx.senderPublicKeyDilithium = "";
    tx.senderPublicKeyFalcon = "";
    tx.metadata = "MiningReward";
    tx.nonce = 0;

    tx.hash = hashOverride;
    if (tx.hash.empty()) {
        tx.hash = tx.getTransactionHash();
    }

    return tx;
}

//
bool Transaction::isMiningRewardFor(const std::string& addr) const {
    return sender == "System" && recipient == addr && metadata == "MiningReward";
}
