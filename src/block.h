#ifndef BLOCK_H
#define BLOCK_H

#include <cstddef>
#include <vector>
#include <string>
#include <ctime>
#include <json/json.h>
#include "transaction.h"
#include "crypto_utils.h"
#include "generated/block_protos.pb.h"
#include "generated/blockchain_protos.pb.h"
#include "generated/transaction_protos.pb.h"

class Block {
private:
    int index;
    std::string previousHash;
    std::vector<Transaction> transactions;
    std::string hash;
    std::string minerAddress;
    int nonce;
    time_t timestamp;
    std::string blockSignature;

    std::string transactionsToString() const;

public:
    std::string keccakHash;
    int difficulty;

    static constexpr double INITIAL_REWARD = 10.0;
    static constexpr double DECAY_RATE = 0.00005;

    // --- Constructors ---
    Block();
    Block(int index, const std::string& previousHash, const std::vector<Transaction>& transactions,
          const std::string& minerAddress, int difficulty, uint64_t timestamp, uint64_t nonce);
    Block(const Block& other);
    Block& operator=(const Block& other);

    // --- Getters ---
    int getIndex() const { return index; }
    std::string getPreviousHash() const { return previousHash; }
    const std::vector<Transaction>& getTransactions() const { return transactions; }
    std::string getHash() const { return hash; }
    std::string getMinerAddress() const { return minerAddress; }
    int getNonce() const { return nonce; }
    time_t getTimestamp() const { return timestamp; }
    std::string getBlockSignature() const { return blockSignature; }

    // --- Setters ---
    void setIndex(int idx) { index = idx; }
    void setPreviousHash(const std::string& prev) { previousHash = prev; }
    void setTransactions(const std::vector<Transaction>& txs) { transactions = txs; }
    void setHash(const std::string& value) { hash = value; }
    void setMinerAddress(const std::string& addr) { minerAddress = addr; }
    void setNonce(int value) { nonce = value; }
    void setSignature(const std::string& signature) { blockSignature = signature; }
    void setTimestamp(time_t ts) { timestamp = ts; }
    void setKeccakHash(const std::string& khash) { keccakHash = khash; }
    void setDifficulty(int diff) { difficulty = diff; }

    // --- Other Functions ---
    bool isGenesisBlock() const { return index == 0 && previousHash == "00000000000000000000000000000000"; }
    void incrementNonce() { nonce++; }
    std::string getTransactionsHash() const;
    bool mineBlock(int difficulty);
    void signBlock(const std::string& minerPrivateKeyPath);
    double calculateMiningReward(int blockIndex, int recentTxCount);
    bool hasValidProofOfWork() const;
    std::string calculateHash() const;
    bool verifyBlockSignature(const std::string& publicKeyPath) const;
    void computeKeccakHash();
    bool isValid(const std::string& prevHash) const;
    bool containsTransaction(const Transaction& tx) const;
    std::string getHashInput() const { return previousHash + std::to_string(timestamp) + std::to_string(nonce); }

    // --- Serialization / Deserialization ---
    void serializeToProtobuf(alyncoin::BlockProto& proto) const;
    bool deserializeFromProtobuf(const alyncoin::BlockProto& proto);
    static Block fromProto(const alyncoin::BlockProto& proto);

    Json::Value toJSON() const;
    static Block fromJSON(const Json::Value& blockJson);
    alyncoin::BlockProto toProtobuf() const;
};

#endif // BLOCK_H
