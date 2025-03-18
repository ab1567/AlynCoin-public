#ifndef BLOCKCHAIN_H
#define BLOCKCHAIN_H

#include <rocksdb/db.h>
#include <boost/asio.hpp>
#include "block.h"
#include "transaction.h"
#include "crypto_utils.h"
#include <vector>
#include <mutex>
#include <atomic>
#include <json/json.h>
#include <cstdint>
#include "generated/block_protos.pb.h"
#include "generated/blockchain_protos.pb.h"
#include "generated/transaction_protos.pb.h"
#include <ctime>
#include <map>
#include <string>
#include <vector>
#include <functional>
#include <unordered_map>
#include <deque>

#define DIFFICULTY 4
#define DEFAULT_PORT 8333
extern std::mutex blockchainMutex;
using boost::asio::ip::tcp;
class Network;

class Blockchain {
private:
    Blockchain();
    std::vector<Block> chain;
    std::deque<int> recentTransactionCounts;
    std::vector<Transaction> pendingTransactions;
    static std::atomic<bool> isMining;
    double blockReward = 10.0;
    int difficulty;
    double miningReward;
    mutable std::mutex mutex;
    Network* network;
    rocksdb::DB* db;
    double totalBurnedSupply = 0.0;

    static constexpr const char* DEV_FUND_ADDRESS = "DevFundWallet";
    double devFundBalance = 0.0;
    std::time_t devFundLastActivity = std::time(nullptr);

    // --- Vesting ---
    struct VestingInfo {
        double lockedAmount;
        uint64_t unlockTimestamp;
    };
    std::unordered_map<std::string, VestingInfo> vestingMap;

    // --- Dev Fund Voting ---
    struct VotingSession {
        std::map<std::string, double> votes; // Map newDevFundAddress to total weight
        std::time_t startTime;
        bool isActive;
    };
    VotingSession votingSession;

    // --- Private Helper Functions ---
    void checkDevFundActivity();
    void distributeDevFund();
    void initiateVotingSession();
    void tallyVotes();
    double getTotalSupply() const;
    void loadVestingInfoFromDB();
    void saveVestingInfoToDB();

    Blockchain(unsigned short port, const std::string& dbPath = "");

public:
    static Blockchain& getInstance(unsigned short port = 8333, const std::string& dbPath = "/root/.alyncoin/blockchain_db");
    Blockchain(const Blockchain&) = delete;
    Blockchain& operator=(const Blockchain&) = delete;
    ~Blockchain();

    // Blockchain Operations
    void adjustDifficulty();
    void syncChain(const Json::Value& jsonData);
    bool saveToDB();
    bool loadFromDB();
    void loadFromPeers();
    void saveTransactionsToDB();
    void loadTransactionsFromDB();
    void reloadBlockchainState();
    void mergeWith(const Blockchain& other);
    void updateFromJSON(const std::string& jsonData);
    void clearPendingTransactions();
    void printPendingTransactions();
    int getIndex() const { return chain.size() - 1; }
    Block createGenesisBlock();
    bool deserializeBlockchain(const std::string& data);
    bool serializeBlockchain(std::string& outData) const;
    void fromJSON(const Json::Value& root);
    void addTransaction(const Transaction& tx);
    std::vector<Transaction> getPendingTransactions() const;
    bool isTransactionValid(const Transaction& tx) const;
    std::string signTransaction(const std::string& privateKeyPath, const std::string& message);
    Block mineBlock(const std::string& minerAddress);
    void startMining(const std::string& minerAddress);
    void stopMining();
    bool hasPendingTransactions() const;
    Block minePendingTransactions(const std::string& minerAddress);
    void setPendingTransactions(const std::vector<Transaction>& transactions);
    bool addBlock(const Block& block);
    void fromProto(const alyncoin::BlockchainProto& protoChain);
    void replaceChain(const std::vector<Block>& newChain);
    const Block& getLatestBlock() const;
    void printBlockchain() const;
    void requestFullSync();
    Block createBlock(const std::string& minerAddress);
    int getRecentTransactionCount();
    void updateTransactionHistory(int newTxCount);
    bool isValidNewBlock(const Block& newBlock);
    const std::vector<Block>& getChain() const;
    Json::Value toJSON() const;
    double getBalance(const std::string& publicKey) const;
    int getBlockCount() const { return chain.size(); }
};

#endif // BLOCKCHAIN_H
