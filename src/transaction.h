#ifndef TRANSACTION_H
#define TRANSACTION_H

#include "generated/transaction_protos.pb.h"
#include "../network/peer_blacklist.h"
#include "hash.h"
#include <cstddef>
#include <fstream>
#include <iostream>
#include <jsoncpp/json/json.h>
#include <string>
#include <vector>

class Transaction {
public:
  Transaction();
  Transaction(const std::string &sender, const std::string &recipient,
              double amount, const std::string &signatureDilithium,
              const std::string &signatureFalcon, std::time_t timestamp);

  std::string getRecipient() const;
  std::string getSender() const;
  double getAmount() const;
  std::string getSignatureDilithium() const;
  std::string getSignatureFalcon() const;
  time_t getTimestamp() const;
  std::string getTransactionHash() const;
  std::string getZkProof() const;
  std::string calculateHash() const;
  std::string toString() const;
  std::string getHash() const;
  std::string getSignature() const;
  std::string getSenderPublicKeyDilithium() const {
    return senderPublicKeyDilithium;
  }
  std::string getSenderPublicKeyFalcon() const { return senderPublicKeyFalcon; }
    void setSenderPublicKeyDilithium(const std::string &key) { senderPublicKeyDilithium = key; }
    void setSenderPublicKeyFalcon(const std::string &key) { senderPublicKeyFalcon = key; }
  void setAmount(double newAmount);
  void setZkProof(const std::string &proof);
  void signTransaction(const std::vector<unsigned char> &dilithiumPrivateKey,
                     const std::vector<unsigned char> &falconPrivateKey);
  bool isValid(const std::string &senderPublicKeyPathDilithium,
               const std::string &senderPublicKeyPathFalcon) const;
     bool isRewardTransaction() const {
         return sender == "System";}

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
  static std::vector<Transaction> loadFromDB();

  // Burn
  static double calculateBurnRate(int recentTxCount);
  void applyBurn(std::string &sender, double &amount, int recentTxCount);
static Transaction createSystemRewardTransaction(const std::string &recipient, double amount);
private:
  std::string sender;
  std::string recipient;
  double amount;
  std::string signatureDilithium;
  std::string hash;
  std::string signatureFalcon;
  time_t timestamp;
  std::string zkProof;
  std::string senderPublicKeyDilithium;
  std::string senderPublicKeyFalcon;
};

#endif // TRANSACTION_H
