#ifndef BLOCKCHAIN_H
#define BLOCKCHAIN_H

#include "generated/block_protos.pb.h"
#include "generated/blockchain_protos.pb.h"
#include "generated/transaction_protos.pb.h"
#include "block.h"
#include "crypto_utils.h"
#include "layer2/state_channel.h"
#include "rollup/rollup_block.h"
#include "transaction.h"
#include <atomic>
#include <boost/asio.hpp>
#include <cstdint>
#include <ctime>
#include "db/db_paths.h"
#include <deque>
#include <functional>
#include <json/json.h>
#include <map>
#include <mutex>
#include <rocksdb/db.h>
#include <string>
#include <unordered_map>
#include <vector>

#define DIFFICULTY 4
#define DEFAULT_PORT 8333
extern std::mutex blockchainMutex;
using boost::asio::ip::tcp;
class Network;
extern double totalSupply;
const double MAX_SUPPLY = 250000000.0;
const size_t MAX_PENDING_TRANSACTIONS = 10000;
class Blockchain {
  friend class Network;

private:
  Blockchain();
  std::vector<Block> chain;
  unsigned short port;
  std::string dbPath;
  double totalBurnedSupply = 0.0;
  std::deque<int> recentTransactionCounts;
  std::vector<Transaction> pendingTransactions;
  static std::atomic<bool> isMining;
  double blockReward = 10.0;
  int difficulty;
  double miningReward;
  mutable std::mutex mutex;
  std::string minerAddress;
  Network *network;
  rocksdb::DB *db;
  std::unordered_map<std::string, double> balances;
  std::vector<RollupBlock> rollupChain;
  static constexpr const char *DEV_FUND_ADDRESS = "DevFundWallet";
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
    std::map<std::string, double> votes;
    std::time_t startTime;
    bool isActive;
  };
  VotingSession votingSession;

  // --- Private Helper Functions ---
  void checkDevFundActivity();
  void distributeDevFund();
  void initiateVotingSession();
  void tallyVotes();
  void loadVestingInfoFromDB();
  void saveVestingInfoToDB();

   Blockchain(unsigned short port, const std::string &dbPath = DBPaths::getBlockchainDB(), bool bindNetwork = true);

public:
  static Blockchain &getInstance(unsigned short port = 8333,
                               const std::string &dbPath = DBPaths::getBlockchainDB(),
                               bool bindNetwork = true);
  Blockchain(const Blockchain &) = delete;
  Blockchain &operator=(const Blockchain &) = delete;
  ~Blockchain();

  // Blockchain Operations
  void adjustDifficulty();
  void syncChain(const Json::Value &jsonData);
  bool saveToDB();
  bool loadFromDB();
  void loadFromPeers();
  void reloadBlockchainState();
  void recalculateBalancesFromChain();
  void mergeWith(const Blockchain &other);
  void updateFromJSON(const std::string &jsonData);
  void clearPendingTransactions();
  void printPendingTransactions();
  int getIndex() const { return chain.size() - 1; }
  void savePendingTransactionsToDB();
  void loadTransactionsFromDB();
  Block createGenesisBlock();
  bool deserializeBlockchain(const std::string &data);
  bool serializeBlockchain(std::string &outData) const;
  void fromJSON(const Json::Value &root);
  void addTransaction(const Transaction &tx);
  std::vector<Transaction> getPendingTransactions() const;
  bool isTransactionValid(const Transaction &tx) const;
  std::vector<unsigned char> signTransaction(const std::vector<unsigned char> &privateKey,
                                           const std::vector<unsigned char> &message);
  void validateChainContinuity() const;
  double calculateBlockReward();
  static Blockchain &getInstanceNoNetwork();
  static Blockchain& getInstanceNoDB();
  std::vector<Block> getAllBlocks();
  // Updated mining function to accept Dilithium + Falcon keys
  Block mineBlock(const std::string &minerAddress);

  void applyVestingSchedule();
  void startMining(const std::string &minerAddress,
                             const std::string &minerDilithiumKey,
                             const std::string &minerFalconKey);
  void stopMining();
  bool hasPendingTransactions() const;
  Block minePendingTransactions(const std::string &minerAddress,
                                          const std::vector<unsigned char> &minerDilithiumPriv,
                                          const std::vector<unsigned char> &minerFalconPriv);
  void setPendingTransactions(const std::vector<Transaction> &transactions);
 double getAverageBlockTime(int recentCount) const;
  // Updated block addition and validation functions
  bool addBlock(const Block &block);
  void loadPendingTransactionsFromDB();
  bool isValidNewBlock(const Block &newBlock);
  double calculateBalance(const std::string &address, const std::map<std::string, double> &tempSnapshot) const;
  void fromProto(const alyncoin::BlockchainProto &protoChain);
  void replaceChain(const std::vector<Block> &newChain);
  const Block &getLatestBlock() const;
  void printBlockchain() const;
  void requestFullSync();
  bool processStateChannelCommitment(const StateChannel &channel);
  std::vector<Transaction>
  aggregateOffChainTxs(const std::vector<Transaction> &offChainTxs);
  Block createRollupBlock(const std::vector<Transaction> &offChainTxs);
  void saveRollupChain() const;
  void loadRollupChain();
  void mergeRollupChain(const std::vector<RollupBlock> &otherChain);
  std::vector<RollupBlock> deserializeRollupChain(const std::string &data);
  RollupBlock deserializeRollupBlock(const std::string &data);
  double getTotalBurnedSupply() const { return totalBurnedSupply; }
  double getTotalSupply() const;
  // Pass dual keys during block creation (optional)
  Block createBlock(const std::string &minerDilithiumKey,
                    const std::string &minerFalconKey);

  int getRecentTransactionCount();
  void updateTransactionHistory(int newTxCount);
  const std::vector<Block> &getChain() const;
  Json::Value toJSON() const;
  void addRollupBlock(const RollupBlock &newRollupBlock);
  bool isRollupBlockValid(const RollupBlock &newRollupBlock) const;
  double getBalance(const std::string &publicKey) const;
  int getBlockCount() const { return chain.size(); }
  void addVestingForEarlySupporter(const std::string &address,
                                   double initialAmount);
  bool castVote(const std::string &voterAddress,
                const std::string &candidateAddress);

    //rollup
   std::unordered_map<std::string, double> getCurrentState() const;
   std::unordered_map<std::string, double> simulateL2StateUpdate(
      const std::unordered_map<std::string, double>& currentState,
      const std::vector<Transaction>& l2Txs) const;

   int getRollupChainSize() const;
   std::string getLastRollupHash() const;
   std::string getLastRollupProof() const;


// Add L2 transaction to pending pool
   void addL2Transaction(const Transaction& tx);
   bool isL2Transaction(const Transaction& tx) const;
   std::vector<Transaction> getPendingL2Transactions() const;
   void clearChain() { chain.clear(); }
};

#endif // BLOCKCHAIN_H
