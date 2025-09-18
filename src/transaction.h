#ifndef TRANSACTION_H
#define TRANSACTION_H

#include <generated/transaction_protos.pb.h>
#include "../network/peer_blacklist.h"
#include "hash.h"
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <json/json.h>
#include <string>
#include <vector>

class Transaction {
public:
  Transaction();
  Transaction(const std::string &sender, const std::string &recipient,
              double amount, const std::string &signatureDilithium,
              const std::string &signatureFalcon, std::time_t timestamp,
              uint64_t nonce = 0);

  std::string getRecipient() const;
  std::string getSender() const;
  double getAmount() const;
  std::string getSignatureDilithium() const;
  std::string getSignatureFalcon() const;
  time_t getTimestamp() const;
  uint64_t getNonce() const;
  std::string getTransactionHash() const;
  std::string getZkProof() const;
  [[deprecated("use getTransactionHash")]]
  std::string hashLegacy() const;
  std::string toString() const;
  std::string getHash() const;
  std::string getSignature() const;
  std::string getSenderPublicKeyDilithium() const {
    return senderPublicKeyDilithium;
  }
  bool isL2() const {
    return metadata.find("L2") == 0 || metadata.find("L2:") == 0;
  }

  std::string getSenderPublicKeyFalcon() const { return senderPublicKeyFalcon; }
  void setSenderPublicKeyDilithium(const std::string &key) {
    senderPublicKeyDilithium = key;
  }
  void setSenderPublicKeyFalcon(const std::string &key) {
    senderPublicKeyFalcon = key;
  }
  void setAmount(double newAmount);
  void setZkProof(const std::string &proof);
  void setNonce(uint64_t value);
  void signTransaction(const std::vector<unsigned char> &dilithiumPrivateKey,
                     const std::vector<unsigned char> &falconPrivateKey);
  bool isValid(const std::string &senderPublicKeyPathDilithium,
               const std::string &senderPublicKeyPathFalcon) const;
  bool isRewardTransaction() const { return sender == "System"; }
  bool isMiningRewardFor(const std::string &addr) const;
  // Protobuf
  std::string serialize() const;
  void serializeToProtobuf(alyncoin::TransactionProto &proto) const;
  bool deserializeFromProtobuf(const alyncoin::TransactionProto &proto);
  static Transaction deserialize(const std::string &data);
  Json::Value toJSON() const;
  static Transaction fromJSON(const Json::Value &txJson);
  static Transaction fromProto(const alyncoin::TransactionProto &proto);
  alyncoin::TransactionProto toProto() const;
  // RocksDB
  static bool saveToDB(const Transaction &tx, int index);
  static std::vector<Transaction> loadAllFromDB();
  // Burn
  static double calculateBurnRate(int recentTxCount);
  static double computeBurnedAmount(double amount, int recentTxCount);
  void applyBurn(std::string &sender, double &amount, int recentTxCount);
  static Transaction createSystemRewardTransaction(
    const std::string &recipient,
    double amount,
    time_t ts,
    const std::string &hashOverride = "");

    void setMetadata(const std::string& meta) { metadata = meta; }
    std::string getMetadata() const { return metadata; }

private:
  std::string sender;
  std::string recipient;
  double amount;
  std::string signatureDilithium;
  std::string hash;
  std::string signatureFalcon;
  time_t timestamp;
  std::string zkProof;
    std::string metadata;
  std::string senderPublicKeyDilithium;
  std::string senderPublicKeyFalcon;
  uint64_t nonce{0};
};

#endif // TRANSACTION_H
