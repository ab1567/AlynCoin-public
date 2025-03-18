#ifndef TRANSACTION_H
#define TRANSACTION_H

#include <cstddef>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <jsoncpp/json/json.h>
#include "hash.h"
#include "generated/transaction_protos.pb.h"  // ✅ Include Protobuf

class Transaction {
public:
    Transaction();
    Transaction(const std::string& sender, const std::string& recipient, double amount, const std::string& signature);

    std::string getRecipient() const;
    std::string getSender() const;
    double getAmount() const;
    std::string getSignature() const;
    time_t getTimestamp() const;
    std::string getTransactionHash() const;
    std::string getHash() const;
    std::string toString() const;
    void setAmount(double newAmount);
    void setSignature(const std::string& sig);
    static Transaction fromProto(const alyncoin::TransactionProto& proto);
    bool isValid(const std::string& senderPublicKeyPath) const;
    void signTransaction(const std::string& privateKeyPath, bool useManualSignature = false);
    std::string calculateHash() const;

    // ✅ Replace JSON serialization with Protobuf
    std::string serialize() const;
    void serializeToProtobuf(alyncoin::TransactionProto& proto) const;
    bool deserializeFromProtobuf(const alyncoin::TransactionProto& proto);
    Json::Value toJSON() const;
    static Transaction deserialize(const std::string& data);
    static Transaction fromJSON(const Json::Value& txJson);
    // ✅ RocksDB Integration for Transactions
    static bool saveToDB(const Transaction& tx, int index);
    static std::vector<Transaction> loadFromDB();

    static double calculateBurnRate(int recentTxCount);
    void applyBurn(std::string& sender, double& amount, int recentTxCount);

private:
    std::string sender;
    std::string recipient;
    double amount;
    std::string signature;
    time_t timestamp;
    std::string hash;
};

#endif // TRANSACTION_H
