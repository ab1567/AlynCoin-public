#include "generated/block_protos.pb.h"
#include "generated/blockchain_protos.pb.h"
#include "blockchain.h"
#include "blake3.h"
#include "difficulty.h"
#include "block_reward.h"
#include "crypto_utils.h"
#include "difficulty.h"
#include "layer2/state_channel.h"
#include "network.h"
#include "rollup/proofs/proof_verifier.h"
#include "rollup/rollup_block.h"
#include "transaction.h"
#include "zk/winterfell_stark.h"
#include "json/json.h"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <locale>
#include <mutex>
#include <sys/stat.h>
#include <thread>

#define ROLLUP_CHAIN_FILE "rollup_chain.dat"
namespace fs = std::filesystem;
const std::string BLOCKCHAIN_DB_PATH = "/root/.alyncoin/blockchain_db";
std::vector<StateChannel> stateChannels;
std::vector<RollupBlock> rollupBlocks;
double totalSupply = 0.0;
// Global mutex for blockchain safety
std::mutex blockchainMutex;
std::atomic<bool> Blockchain::isMining{false};

Blockchain::Blockchain()
    : difficulty(4), miningReward(10.0), db(nullptr), totalBurnedSupply(0.0),
      network(nullptr) {
  std::cout << "[DEBUG] Default Blockchain constructor called.\n";
}

// ✅ **Constructor: Open RocksDB**
Blockchain::Blockchain(unsigned short port, const std::string &dbPath)
    : difficulty(4), miningReward(10.0) {
  network = &Network::getInstance(port, this);
  std::cout << "[DEBUG] Initializing Blockchain..." << std::endl;

  std::string dbPathFinal = BLOCKCHAIN_DB_PATH;
  if (!dbPath.empty()) {
    dbPathFinal = dbPath;
    std::cout << "📁 Using custom DB path: " << dbPathFinal << "\n";
  }

  if (!fs::exists(dbPathFinal)) {
    std::cerr << "⚠️ RocksDB directory missing. Creating: " << dbPathFinal
              << "\n";
    fs::create_directories(dbPathFinal);
  }

  rocksdb::Options options;
  options.create_if_missing = true;
  rocksdb::Status status = rocksdb::DB::Open(options, dbPathFinal, &db);
  if (!status.ok()) {
    std::cerr << "❌ [ERROR] Failed to open RocksDB: " << status.ToString()
              << std::endl;
    exit(1);
  }

  // Load blockchain data
  std::cout << "[DEBUG] Attempting to load blockchain from DB...\n";
  loadFromDB();

  // Load existing vesting info (if previously applied)
  loadVestingInfoFromDB();

  // ✅ Check if vesting marker exists
  std::string vestingMarker;
  status =
      db->Get(rocksdb::ReadOptions(), "vesting_initialized", &vestingMarker);

  if (!status.ok()) {
    std::cout << "⏳ Applying vesting schedule for early supporters...\n";
    applyVestingSchedule(); // Call new function
    db->Put(rocksdb::WriteOptions(), "vesting_initialized", "true");
    std::cout << "✅ Vesting applied & marker set.\n";
  } else {
    std::cout << "✅ Vesting already initialized. Skipping.\n";
  }
}

// ✅ **Destructor: Close RocksDB**
Blockchain::~Blockchain() {
  if (db) {
    delete db;
    db = nullptr; // ✅ Prevent potential use-after-free issues
  }
}

// ✅ **Validate a Transaction**
bool Blockchain::isTransactionValid(const Transaction &tx) const {
  std::string sender = tx.getSender();

  if (sender == "System") return true;

  auto it = vestingMap.find(sender);
  if (it != vestingMap.end()) {
    double locked = it->second.lockedAmount;
    uint64_t unlockTime = it->second.unlockTimestamp;
    double senderBalance = getBalance(sender);

    if (std::time(nullptr) < unlockTime && (senderBalance - locked < tx.getAmount())) {
      std::cerr << "⛔ [VESTING] Transaction rejected! Locked balance in effect for: " << sender << "\n";
      return false;
    }
  }

  try {
    std::vector<unsigned char> msgBytes = Crypto::fromHex(tx.getHash());
    std::vector<unsigned char> sigDilithium = Crypto::fromHex(tx.getSignatureDilithium());
    std::vector<unsigned char> sigFalcon = Crypto::fromHex(tx.getSignatureFalcon());
    std::vector<unsigned char> pubKeyDilithium = Crypto::fromHex(tx.getSenderPublicKeyDilithium());
    std::vector<unsigned char> pubKeyFalcon = Crypto::fromHex(tx.getSenderPublicKeyFalcon());

    if (!Crypto::verifyWithDilithium(msgBytes, sigDilithium, pubKeyDilithium)) return false;
    if (!Crypto::verifyWithFalcon(msgBytes, sigFalcon, pubKeyFalcon)) return false;

  } catch (const std::exception &e) {
    std::cerr << "❌ Exception during isTransactionValid: " << e.what() << "\n";
    return false;
  }

  std::cout << "✅ Transaction verified successfully for: " << sender << "\n";
  return true;
}

// ✅ Create the Genesis Block Properly
Block Blockchain::createGenesisBlock() {
  std::vector<Transaction> transactions;
  Block genesis(0, "00000000000000000000000000000000", transactions, "System",
                difficulty, std::time(nullptr), 0);
  std::cout << "[DEBUG] Genesis Block created with hash: " << genesis.getHash()
            << std::endl;
  std::string keyPath = getPrivateKeyPath("System");
  std::cout << "[DEBUG] Genesis private key path: " << keyPath << std::endl;
  if (!fs::exists(keyPath)) {
    std::cerr
        << "⚠️ [WARNING] Private key missing for Genesis Block! Generating...\n";
    Crypto::generateKeysForUser("System");
  }

  std::string signature = Crypto::signMessage(genesis.getHash(), keyPath, true);
  if (signature.empty()) {
    std::cerr << "❌ [ERROR] Genesis block signature failed!" << std::endl;
    exit(1);
  }
  genesis.setSignature(signature);

  return genesis;
}

// ✅ Adds block, applies smart burn, and broadcasts to peers
bool Blockchain::addBlock(const Block &newBlock) {
  if (chain.empty()) {
    if (!newBlock.isGenesisBlock()) {
      std::cerr << "❌ First block must be Genesis Block!\n";
      return false;
    }
  } else {
    Block lastBlock = chain.back();
    if (!newBlock.isValid(lastBlock.getHash())) {
      std::cerr << "❌ Invalid block detected. Rejecting!\n";
      return false;
    }
  }

  // Push block with proof (proof is already in block)
  chain.push_back(newBlock);

  // Remove included transactions
  for (const auto &tx : newBlock.getTransactions()) {
    pendingTransactions.erase(
        std::remove_if(pendingTransactions.begin(), pendingTransactions.end(),
                       [&tx](const Transaction &pendingTx) {
                         return pendingTx.getHash() == tx.getHash();
                       }),
        pendingTransactions.end());
  }

  saveToDB();
  saveTransactionsToDB();

  std::cout << "✅ Block added to blockchain. Pending TXs updated.\n";
  return true;
}

// ✅ **Singleton Instance**
Blockchain &Blockchain::getInstance(unsigned short port,
                                    const std::string &dbPath) {
  static Blockchain instance(port, dbPath);
  return instance;
}

//
const std::vector<Block> &Blockchain::getChain() const { return chain; }
//
void Blockchain::loadFromPeers() {
  if (!network) {
    std::cerr << "❌ Error: Network module is not initialized!" << std::endl;
    return;
  }

  std::vector<std::string> peers = network->getPeers();
  if (peers.empty()) {
    std::cerr << "⚠️ No peers available for sync!" << std::endl;
    return;
  }

  for (const auto &peer : peers) {
    network->requestBlockchainSync(peer); // ✅ Pass argument
  }
}

//
void Blockchain::clearPendingTransactions() {
  pendingTransactions.clear(); // ✅ No mutex lock needed

  // 🛠 Ensure "data/" directory exists
  if (!std::filesystem::exists("data")) {
    std::filesystem::create_directory("data");
  }

  // ✅ Clear the transactions file
  std::ofstream outFile("data/transactions.json", std::ios::trunc);
  if (outFile.is_open()) {
    outFile << "[]"; // Empty JSON array
    outFile.close();
  } else {
    std::cerr << "❌ [ERROR] Failed to open transactions.json for clearing!" << std::endl;
  }

  std::cout << "🚨 Cleared all pending transactions after mining.\n";
}

// ✅ Helper function to check if a file exists
bool fileExists(const std::string &filename) {
  struct stat buffer;
  return (stat(filename.c_str(), &buffer) == 0);
}
//
void Blockchain::mergeWith(const Blockchain &other) {
  if (other.chain.size() <= chain.size()) {
    std::cerr << "⚠️ Merge skipped: Local chain is longer or equal.\n";
    return;
  }

  std::vector<Block> newChain;
  for (const auto &block : other.chain) {
    if (newChain.empty() || block.isValid(newChain.back().getHash())) {
      newChain.push_back(block);
    } else {
      std::cerr
          << "❌ [ERROR] Invalid block detected during merge! Skipping...\n";
    }
  }

  if (newChain.size() > chain.size()) {
    std::cout << "✅ Replacing current blockchain with a longer valid chain!\n";
    chain = newChain;
    saveToDB();
  } else {
    std::cerr << "⚠️ New chain was not longer. Keeping existing chain.\n";
  }
}

// ✅ **Check for pending transactions**
bool Blockchain::hasPendingTransactions() const {
  return !pendingTransactions.empty(); // ✅ Only checks, does not modify!
}
//
void Blockchain::setPendingTransactions(
    const std::vector<Transaction> &transactions) {
  pendingTransactions = transactions;
}

// ✅ Mine pending transactions and dynamically adjust difficulty
Block Blockchain::minePendingTransactions(const std::string &minerAddress,
                                          const std::vector<unsigned char> &minerDilithiumPriv,
                                          const std::vector<unsigned char> &minerFalconPriv) {
  auto t1 = std::chrono::high_resolution_clock::now();
  std::cout << "[DEBUG] Waiting on blockchainMutex in minePendingTransactions()...\n";
  std::lock_guard<std::mutex> lock(blockchainMutex);
  auto t2 = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> elapsed = t2 - t1;
  std::cout << "[DEBUG] Acquired mutex in " << elapsed.count() << " seconds.\n";

  if (pendingTransactions.empty()) {
    std::cerr << "⚠️ No transactions to mine!\n";
    return Block();
  }

  std::vector<Transaction> validTransactions;
  std::cout << "[DEBUG] Validating and preparing transactions...\n";

  for (const auto &tx : pendingTransactions) {
    if (isTransactionValid(tx)) {
      double originalAmount = tx.getAmount();
      std::string sender = tx.getSender();
      std::string recipient = tx.getRecipient();
      std::string sigDil = tx.getSignatureDilithium();
      std::string sigFal = tx.getSignatureFalcon();
      std::time_t timestamp = tx.getTimestamp();

      // Optional: truncate overly large signatures to avoid malformed crashes
      if (sigDil.length() > 5000) sigDil = sigDil.substr(0, 5000);
      if (sigFal.length() > 5000) sigFal = sigFal.substr(0, 5000);

      double txActivity = static_cast<double>(getRecentTransactionCount());
      double burnRate = std::min(std::max(0.01, txActivity / 1000.0), 0.05);

      double feeAmount = originalAmount * 0.01;
      double burnAmount = feeAmount * burnRate;
      double devFundAmount = feeAmount - burnAmount;
      double finalAmount = originalAmount - feeAmount;

      totalBurnedSupply += burnAmount;

      validTransactions.emplace_back(sender, recipient, finalAmount, sigDil, sigFal, timestamp);
      validTransactions.emplace_back(sender, DEV_FUND_ADDRESS, devFundAmount, sigDil, sigFal, timestamp);

      std::cout << "🔥 Burned: " << burnAmount
                << ", 💰 Dev Fund: " << devFundAmount
                << ", Final Sent: " << finalAmount << std::endl;
    } else {
      std::cerr << "❌ Invalid transaction detected. Skipping.\n";
    }
  }

  std::cout << "[DEBUG] Applying capped supply reward logic...\n";
  if (totalSupply < MAX_SUPPLY) {
    double reward = calculateBlockReward();
    if (totalSupply + reward > MAX_SUPPLY)
      reward = MAX_SUPPLY - totalSupply;

  validTransactions.push_back(Transaction::createSystemRewardTransaction(minerAddress, reward));

    totalSupply += reward;
    std::cout << "⛏️ Block reward: " << reward << " AlynCoin\n";
  } else {
    std::cerr << "🚫 Block reward skipped. Max supply reached.\n";
  }

  Block lastBlock = getLatestBlock();
  std::cout << "[DEBUG] Last block hash: " << lastBlock.getHash() << "\n";

  std::cout << "[DEBUG] Adjusting difficulty...\n";
  adjustDifficulty();

  std::cout << "[DEBUG] Creating new block...\n";
  Block newBlock(chain.size(), lastBlock.getHash(), validTransactions,
                 minerAddress, difficulty, std::time(nullptr), std::time(nullptr));

  std::cout << "[DEBUG] Starting PoW mining with difficulty " << difficulty << "...\n";
  newBlock.mineBlock(difficulty);

  std::string blockHashHex = newBlock.getHash();
  std::vector<unsigned char> hashBytes = Crypto::fromHex(blockHashHex);

  if (hashBytes.size() != 32) {
    std::cerr << "[ERROR] Block hash is not 32 bytes! Cannot sign.\n";
    return Block();
  }

  std::vector<unsigned char> dilithiumSig = Crypto::signWithDilithium(hashBytes, minerDilithiumPriv);
  std::vector<unsigned char> falconSig = Crypto::signWithFalcon(hashBytes, minerFalconPriv);

  newBlock.setDilithiumSignature(Crypto::toHex(dilithiumSig));
  newBlock.setFalconSignature(Crypto::toHex(falconSig));

  std::cout << "[DEBUG] Adding block to chain...\n";
  addBlock(newBlock);

  std::cout << "[DEBUG] Re-adjusting difficulty post block...\n";
  adjustDifficulty();

  std::cout << "[DEBUG] Clearing pending transactions...\n";
  clearPendingTransactions();

  std::cout << "[DEBUG] Saving blockchain state to DB...\n";
  saveToDB();

  std::cout << "✅ Block mined successfully. Total burned: " << totalBurnedSupply << " AlynCoin\n";
  return newBlock;
}

// ✅ **Sync Blockchain**
void Blockchain::syncChain(const Json::Value &jsonData) {
  std::lock_guard<std::mutex> lock(blockchainMutex);

  std::vector<Block> newChain;
  for (const auto &blockJson : jsonData["chain"]) {
    alyncoin::BlockProto protoBlock;
    if (!protoBlock.ParseFromString(blockJson.asString())) {
      std::cerr << "❌ [ERROR] Failed to parse Protobuf block data!\n";
      return;
    }

    Block newBlock;
    if (!newBlock.deserializeFromProtobuf(protoBlock)) {
      std::cerr << "❌ [ERROR] Invalid block format during deserialization!\n";
      return;
    }

    newChain.push_back(newBlock);
  }

  if (newChain.size() > chain.size()) {
    chain = newChain;
    saveToDB();
    std::cout
        << "✅ Blockchain successfully synchronized with a longer chain!\n";
  } else {
    std::cerr
        << "⚠️ [WARNING] Received chain was not longer. No changes applied.\n";
  }
}

// ✅ **Start Mining**
void Blockchain::startMining(const std::string &minerAddress,
                             const std::string &minerDilithiumKey,
                             const std::string &minerFalconKey) {
  if (isMining.load()) {
    std::cout << "⚠️ Mining is already running!" << std::endl;
    return;
  }

  isMining.store(true);

  std::thread([this, minerAddress, minerDilithiumKey, minerFalconKey]() {
    while (isMining.load()) {
      reloadBlockchainState();

      if (pendingTransactions.empty()) {
        std::cout << "⏳ No transactions to mine. Waiting...\n";
        std::this_thread::sleep_for(std::chrono::seconds(5));
        continue;
      }

      std::vector<unsigned char> dilithiumPriv = Crypto::fromHex(minerDilithiumKey);
      std::vector<unsigned char> falconPriv = Crypto::fromHex(minerFalconKey);

      Block newBlock = minePendingTransactions(minerAddress, dilithiumPriv, falconPriv);
      addBlock(newBlock);

      std::this_thread::sleep_for(std::chrono::seconds(2));
    }
  }).detach();
}

// ✅ **Stop Mining**
void Blockchain::stopMining() {
  isMining.store(false);
  std::cout << "⛔ Mining stopped!\n";
}

// ✅ **Reload Blockchain State**
void Blockchain::reloadBlockchainState() {
  loadFromDB();
  loadTransactionsFromDB();
  std::cout << "✅ Blockchain and transactions reloaded!\n";
}

// ✅ **Print Blockchain**
void Blockchain::printBlockchain() const {
  std::unordered_set<std::string> seenHashes; // Track already printed blocks

  std::cout << "=== AlynCoin Blockchain ===\n";
  for (const Block &block : chain) {
    if (seenHashes.find(block.getHash()) != seenHashes.end()) {
      continue; // Skip duplicate blocks
    }
    seenHashes.insert(block.getHash());

    std::cout << "Block Index: " << block.getIndex() << "\n";
    std::cout << "Hash: " << block.getHash() << "\n";
    std::cout << "Previous Hash: " << block.getPreviousHash() << "\n";
    std::cout << "Miner: " << block.getMinerAddress() << "\n";
    std::cout << "Nonce: " << block.getNonce() << "\n";
    std::cout << "Timestamp: " << block.getTimestamp() << "\n";
    std::cout << "Transactions: " << block.getTransactions().size() << "\n";
    std::cout << "---------------------------\n";
  }
  std::cout << "===========================\n";
  std::cout << "🔥 Total Burned Supply: " << totalBurnedSupply
            << " AlynCoin 🔥\n";
}

// ✅ **Show pending transactions (before they are mined)**
void Blockchain::printPendingTransactions() {
  if (!pendingTransactions.empty()) {
    std::cout << "✅ Pending transactions available.\n";
  } else {
    std::cout << "✅ No pending transactions.\n";
  }
}

// ✅ **Add a new transaction**
void Blockchain::addTransaction(const Transaction &tx) {
  std::lock_guard<std::mutex> lock(blockchainMutex);

  // Lowercase sender name
  std::string senderLower = tx.getSender();
  std::transform(senderLower.begin(), senderLower.end(), senderLower.begin(),
                 ::tolower);

  // Check if public key exists, generate if missing
  std::string keyDir = KEY_DIR;
  std::string publicKeyPath = keyDir + senderLower + "_public.pem";

  if (!fs::exists(publicKeyPath)) {
    std::cerr << "⚠️ [WARNING] Public key missing for " << senderLower
              << "! Generating now...\n";
    Crypto::generateKeysForUser(senderLower);
    std::this_thread::sleep_for(
        std::chrono::milliseconds(500)); // Small wait to ensure key generation
  }

  // Update balances
  balances[tx.getSender()] -= tx.getAmount();
  balances[tx.getRecipient()] += tx.getAmount();

  // Monitor Dev Fund activity
  if (tx.getSender() == DEV_FUND_ADDRESS ||
      tx.getRecipient() == DEV_FUND_ADDRESS) {
    devFundLastActivity = std::time(nullptr);
    checkDevFundActivity();
  }

  // Add to pending transactions
  pendingTransactions.push_back(tx);
  saveTransactionsToDB();

  std::cout << "✅ Transaction added. Pending count: "
            << pendingTransactions.size() << "\n";
}

// ✅ **Get balance of a public key**
double Blockchain::getBalance(const std::string &publicKey) const {
  auto it = balances.find(publicKey);
  if (it != balances.end()) {
    return it->second;
  }
  return 0.0;
}

// ✅ **Save Transactions to RocksDB**
void Blockchain::saveTransactionsToDB() {
  if (!db) {
    std::cerr << "❌ Database not initialized. Cannot save transactions.\n";
    return;
  }

  std::cout << "📦 [DEBUG] Saving pending transactions to RocksDB...\n";

  std::thread([this]() {
    rocksdb::WriteBatch batch;
    Json::StreamWriterBuilder writer;
    {
      std::lock_guard<std::mutex> lock(
          blockchainMutex); // ✅ Lock only inside scope
      for (size_t i = 0; i < pendingTransactions.size(); i++) {
        Json::Value txJson = pendingTransactions[i].toJSON();
        txJson["timestamp"] = static_cast<Json::Int64>(
            pendingTransactions[i].getTimestamp()); // Ensure timestamp
        std::string txData = Json::writeString(writer, txJson);
        batch.Put("tx_" + std::to_string(i), txData);
      }
    } // ✅ Mutex automatically unlocks

    rocksdb::Status status = db->Write(rocksdb::WriteOptions(), &batch);
    if (!status.ok()) {
      std::cerr << "❌ Error saving transactions to RocksDB: "
                << status.ToString() << std::endl;
    } else {
      std::cout << "✅ Transactions successfully saved to RocksDB.\n";
    }
  }).detach(); // ✅ Run asynchronously, without blocking the mutex
}

// ✅ **Save Blockchain to RocksDB using Protobuf**
bool Blockchain::saveToDB() {
  std::cout << "[DEBUG] Attempting to save blockchain to DB..." << std::endl;
  if (!db) {
    std::cerr << "❌ RocksDB not initialized!\n";
    return false;
  }

  alyncoin::BlockchainProto blockchainProto;
  for (const auto &block : chain) {
    alyncoin::BlockProto *blockProto = blockchainProto.add_blocks();
    *blockProto = block.toProtobuf();
  }

  std::string serializedData;
  blockchainProto.SerializeToString(&serializedData);

  rocksdb::Status status =
      db->Put(rocksdb::WriteOptions(), "blockchain", serializedData);

  if (!status.ok()) {
    std::cerr << "❌ [ERROR] Failed to save blockchain: " << status.ToString()
              << "\n";
    return false;
  }

  // ✅ Save total burned supply
  db->Put(rocksdb::WriteOptions(), "burned_supply",
          std::to_string(totalBurnedSupply));

  std::cout << "✅ Blockchain saved successfully!\n";
  saveVestingInfoToDB();
  return true;
}

// ✅ **Load Blockchain from RocksDB using Protobuf**
bool Blockchain::loadFromDB() {
  std::cout << "[DEBUG] Attempting to load blockchain from DB..." << std::endl;
  if (!db) {
    std::cerr << "❌ RocksDB not initialized!\n";
    return false;
  }

  std::string serializedBlockchain;
  rocksdb::Status status =
      db->Get(rocksdb::ReadOptions(), "blockchain", &serializedBlockchain);
  if (!status.ok()) {
    std::cerr << "⚠️ RocksDB blockchain not found. Creating Genesis Block.\n";
    chain.push_back(createGenesisBlock());
    saveToDB(); // Save genesis block

    // 🔥 Apply vesting ONLY after fresh genesis block:
    std::cout << "⏳ Applying vesting schedule for early supporters...\n";
    applyVestingSchedule();
    db->Put(rocksdb::WriteOptions(), "vesting_initialized", "true");
    std::cout << "✅ Vesting applied & marker set.\n";

    return true;
  }

  alyncoin::BlockchainProto blockchainProto;
  if (!blockchainProto.ParseFromString(serializedBlockchain)) {
    std::cerr << "❌ [ERROR] Failed to parse blockchain Protobuf data!\n";
    return false;
  }

  chain.clear();
  for (const auto &blockProto : blockchainProto.blocks()) {
    chain.push_back(Block::fromProto(blockProto));
  }

  // ✅ Load total burned supply
  std::string burnedSupplyStr;
  status = db->Get(rocksdb::ReadOptions(), "burned_supply", &burnedSupplyStr);
  if (status.ok()) {
    totalBurnedSupply = std::stod(burnedSupplyStr);
  } else {
    totalBurnedSupply = 0.0;
  }

  // 🟢 Check vesting marker:
  std::string vestingFlag;
  status = db->Get(rocksdb::ReadOptions(), "vesting_initialized", &vestingFlag);
  if (status.ok() && vestingFlag == "true") {
    std::cout << "⏩ Vesting already initialized. Skipping...\n";
  } else {
    std::cout << "⏳ Applying vesting schedule for early supporters...\n";
    applyVestingSchedule();
    db->Put(rocksdb::WriteOptions(), "vesting_initialized", "true");
    std::cout << "✅ Vesting applied & marker set.\n";
  }

  std::cout << "✅ Blockchain loaded successfully!\n";
  return true;
}

// ✅ Save vesting data to DB
void Blockchain::saveVestingInfoToDB() {
  if (!db)
    return;

  rocksdb::WriteBatch batch;
  for (const auto &pair : vestingMap) {
    std::string key = "vesting_" + pair.first;
    Json::Value vestingJson;
    vestingJson["lockedAmount"] = pair.second.lockedAmount;
    vestingJson["unlockTimestamp"] =
        static_cast<Json::UInt64>(pair.second.unlockTimestamp);

    Json::StreamWriterBuilder writer;
    std::string data = Json::writeString(writer, vestingJson);
    batch.Put(key, data);
  }
  db->Write(rocksdb::WriteOptions(), &batch);
}

// ✅ Load vesting data from DB
void Blockchain::loadVestingInfoFromDB() {
  if (!db)
    return;

  rocksdb::Iterator *it = db->NewIterator(rocksdb::ReadOptions());
  for (it->SeekToFirst(); it->Valid(); it->Next()) {
    std::string key = it->key().ToString();
    if (key.find("vesting_") != 0)
      continue;

    std::string address = key.substr(8);
    Json::Value vestingJson;
    Json::CharReaderBuilder reader;
    std::istringstream stream(it->value().ToString());
    std::string errs;

    if (Json::parseFromStream(reader, stream, &vestingJson, &errs)) {
      if (vestingJson.isObject() && vestingJson.isMember("lockedAmount") &&
          vestingJson.isMember("unlockTimestamp")) {
        VestingInfo info;
        info.lockedAmount = vestingJson["lockedAmount"].asDouble();
        info.unlockTimestamp = vestingJson["unlockTimestamp"].asUInt64();
        vestingMap[address] = info;
      } else {
        std::cerr << "⚠️ Invalid vesting JSON for address: " << address
                  << ", skipping.\n";
      }
    } else {
      std::cerr << "⚠️ JSON parsing error for vesting key: " << key
                << " Error: " << errs << "\n";
    }
  }
  delete it;
}

// vesting
void Blockchain::addVestingForEarlySupporter(const std::string &address,
                                             double initialAmount) {
  VestingInfo info;
  info.lockedAmount = initialAmount * 0.5; // 50% locked
  info.unlockTimestamp =
      std::time(nullptr) + (6 * 30 * 24 * 60 * 60); // 6 months
  vestingMap[address] = info;
  saveVestingInfoToDB();
}
//
void Blockchain::applyVestingSchedule() {
  for (int i = 1; i <= 10000; ++i) {
    std::string supporterAddress = "supporter" + std::to_string(i);
    double initialAmount = 10000.0; // Keep same allocation logic
    addVestingForEarlySupporter(supporterAddress, initialAmount);
  }
  saveVestingInfoToDB();
}

// ✅ Serialize Blockchain to Protobuf
bool Blockchain::serializeBlockchain(std::string &outData) const {
  alyncoin::BlockchainProto blockchainProto;

  for (const auto &block : chain) {
    auto *protoBlock = blockchainProto.add_blocks();
    block.serializeToProtobuf(*protoBlock);
  }

  for (const auto &tx : pendingTransactions) {
    auto *txProto = blockchainProto.add_pending_transactions();
    tx.serializeToProtobuf(*txProto);
  }

  blockchainProto.set_difficulty(difficulty);
  blockchainProto.set_block_reward(blockReward);

  if (!blockchainProto.SerializeToString(&outData)) {
    std::cerr
        << "❌ [ERROR] Failed to serialize blockchain to Protobuf format!\n";
    return false;
  }

  std::cout << "📡 [DEBUG] Serialized Blockchain Data (Size: " << outData.size()
            << " bytes)\n";
  std::cout << "📡 [DEBUG] First 100 Bytes of Serialized Data: "
            << outData.substr(0, 100) << "\n";

  return true;
}

// ✅ Deserialize Blockchain from Protobuf
bool Blockchain::deserializeBlockchain(const std::string &data) {
  std::lock_guard<std::mutex> lock(blockchainMutex);

  if (data.empty()) {
    std::cerr << "❌ [ERROR] Received empty Protobuf blockchain data!\n";
    return false;
  }

  std::cout << "📡 [DEBUG] Received Blockchain Data (Size: " << data.size()
            << " bytes)\n";
  std::cout << "📡 [DEBUG] First 100 bytes: " << data.substr(0, 100) << "...\n";

  alyncoin::BlockchainProto protoChain;
  if (!protoChain.ParseFromString(data)) {
    std::cerr << "❌ [ERROR] Failed to parse Protobuf blockchain data!\n";
    std::cerr << "🔍 [DEBUG] Raw data length: " << data.size() << " bytes\n";
    return false;
  }

  chain.clear();
  pendingTransactions.clear();

  difficulty = protoChain.difficulty();
  blockReward = protoChain.block_reward();

  for (const auto &blockProto : protoChain.blocks()) {
    Block block;
    if (!block.deserializeFromProtobuf(blockProto)) {
      std::cerr << "❌ [ERROR] Invalid block format during deserialization!\n";
      return false;
    }
    chain.push_back(block);
  }

  for (const auto &txProto : protoChain.pending_transactions()) {
    Transaction tx;
    if (!tx.deserializeFromProtobuf(txProto)) {
      std::cerr << "❌ [ERROR] Invalid transaction format!\n";
      return false;
    }
    pendingTransactions.push_back(tx);
  }

  std::cout << "✅ Blockchain deserialization completed! Blocks: "
            << chain.size()
            << ", Pending Transactions: " << pendingTransactions.size()
            << std::endl;
  return true;
}
//
// ✅ Convert Protobuf back to Block
// ✅ Correct version already in blockchain.cpp:
void Blockchain::fromProto(const alyncoin::BlockchainProto &protoChain) {
  std::lock_guard<std::mutex> lock(blockchainMutex);
  chain.clear();

  for (const auto &protoBlock : protoChain.blocks()) {
    Block newBlock;

    newBlock.setIndex(protoBlock.index());
    newBlock.setTimestamp(protoBlock.timestamp());
    newBlock.setPreviousHash(protoBlock.previous_hash());
    newBlock.setHash(protoBlock.hash());
    newBlock.setMinerAddress(protoBlock.miner_address());
    newBlock.setNonce(protoBlock.nonce());
    newBlock.setDifficulty(protoBlock.difficulty());

    if (!protoBlock.block_signature().empty())
      newBlock.setSignature(protoBlock.block_signature());

    if (!protoBlock.keccak_hash().empty())
      newBlock.setKeccakHash(protoBlock.keccak_hash());

    std::vector<Transaction> transactions;
    for (const auto &protoTx : protoBlock.transactions()) {
      Transaction tx;
      if (tx.deserializeFromProtobuf(protoTx)) {
        transactions.push_back(tx);
      } else {
        std::cerr << "❌ [ERROR] Invalid transaction skipped in block index "
                  << newBlock.getIndex() << "\n";
      }
    }
    newBlock.setTransactions(transactions);

    chain.push_back(newBlock);
  }
}

// ✅ **Replace blockchain if a longer valid chain is found**
void Blockchain::replaceChain(const std::vector<Block> &newChain) {
  std::lock_guard<std::mutex> lock(blockchainMutex);
  if (newChain.size() > chain.size()) {
    chain = newChain;
    saveToDB();
    std::cout << "✅ Blockchain replaced with a longer valid chain!"
              << std::endl;
  }
}
//
bool Blockchain::isValidNewBlock(const Block &newBlock) {
  if (chain.empty()) return false;

  Block lastBlock = getLatestBlock();
  if (newBlock.getPreviousHash() != lastBlock.getHash()) {
    std::cerr << "❌ Previous Hash Mismatch!\n";
    return false;
  }

  if (!newBlock.hasValidProofOfWork()) {
    std::cerr << "❌ Invalid PoW Detected!\n";
    return false;
  }

  std::string txRoot = newBlock.getTransactionsHash();
  if (!WinterfellStark::verifyProof(newBlock.getZkProof(), newBlock.getHash(), newBlock.getPreviousHash(), txRoot)) {
    std::cerr << "❌ zk-STARK Proof Verification Failed!\n";
    return false;
  }

  std::string computedKeccak = Crypto::keccak256(newBlock.getHash());
  if (computedKeccak != newBlock.keccakHash) {
    std::cerr << "❌ Keccak Validation Failed!\n";
    return false;
  }

  std::vector<unsigned char> hashBytes;
  try {
    hashBytes = Crypto::fromHex(newBlock.getHash());
  } catch (const std::exception &ex) {
    std::cerr << "❌ Failed to decode block hash: " << ex.what() << "\n";
    return false;
  }

  std::vector<unsigned char> sigDil, sigFal;
  try {
    sigDil = Crypto::fromHex(newBlock.getDilithiumSignature());
    sigFal = Crypto::fromHex(newBlock.getFalconSignature());
  } catch (const std::exception &ex) {
    std::cerr << "❌ Failed to decode block signatures: " << ex.what() << "\n";
    return false;
  }

  std::vector<unsigned char> pubKeyDil = Crypto::getPublicKeyDilithium(newBlock.getMinerAddress());
  std::vector<unsigned char> pubKeyFal = Crypto::getPublicKeyFalcon(newBlock.getMinerAddress());

  if (!Crypto::verifyWithDilithium(hashBytes, sigDil, pubKeyDil)) {
    std::cerr << "❌ Dilithium Block Signature Verification Failed!\n";
    return false;
  }

  if (!Crypto::verifyWithFalcon(hashBytes, sigFal, pubKeyFal)) {
    std::cerr << "❌ Falcon Block Signature Verification Failed!\n";
    return false;
  }

  std::cout << "✅ New Block Passed Validation.\n";
  return true;
}

// ✅ **Load Transactions from RocksDB**
void Blockchain::loadTransactionsFromDB() {
  if (!db) {
    std::cerr
        << "❌ [ERROR] Database not initialized. Cannot load transactions.\n";
    return;
  }

  std::cout << "🔄 [INFO] Loading transactions from RocksDB...\n";

  rocksdb::Iterator *it = db->NewIterator(rocksdb::ReadOptions());
  pendingTransactions.clear();

  for (it->Seek("tx_"); it->Valid() && it->key().starts_with("tx_");
       it->Next()) {
    Json::Value txJson;
    Json::CharReaderBuilder reader;
    std::string errs;
    std::istringstream stream(it->value().ToString());

    // ✅ Prevent excessively large transactions
    if (stream.str().size() > 2048) {
      std::cerr << "⚠️ [WARNING] Transaction too large. Possible corruption. "
                   "Skipping...\n";
      continue;
    }

    if (!Json::parseFromStream(reader, stream, &txJson, &errs)) {
      std::cerr << "❌ [ERROR] Failed to parse transaction JSON for key: "
                << it->key().ToString() << "! Skipping transaction.\n";
      continue;
    }

    try {
      Transaction tx = Transaction::fromJSON(txJson);
      if (tx.getAmount() > 0 && !tx.getSender().empty() &&
          !tx.getRecipient().empty()) {
        pendingTransactions.push_back(tx);
      } else {
        std::cerr << "⚠️ [WARNING] Invalid transaction detected! Skipping.\n";
      }
    } catch (const std::exception &e) {
      std::cerr << "❌ [ERROR] Exception while parsing transaction: "
                << e.what() << std::endl;
    }
  }

  delete it;
  std::cout << "✅ Transactions loaded successfully! Pending count: "
            << pendingTransactions.size() << std::endl;
}

//
std::vector<unsigned char> Blockchain::signTransaction(
    const std::vector<unsigned char>& privateKey,
    const std::vector<unsigned char>& message) {
  return Crypto::signWithDilithium(message, privateKey);
}


// ✅ **Create Block Properly Before Mining**
Block Blockchain::createBlock(const std::string &minerDilithiumKey,
                              const std::string &minerFalconKey) {
std::cout << "[DEBUG] Starting minePendingTransactions()..." << std::endl;
std::cout << "[DEBUG] Pending tx count: " << pendingTransactions.size() << std::endl;

  std::vector<Transaction> validTransactions;
  for (const auto &tx : pendingTransactions) {
    if (tx.isValid(tx.getSenderPublicKeyDilithium(),
                   tx.getSenderPublicKeyFalcon())) {
      validTransactions.push_back(tx);
    }
  }

  // ✅ Fix: Generate miner address based on miner keys
  std::string minerAddress = Crypto::generateMinerAddress();

  Block newBlock(chain.size(), getLatestBlock().getHash(), validTransactions,
                 minerAddress, difficulty, std::time(nullptr),
                 0 // Nonce start at 0
  );
  return newBlock;
}

// ✅ Unified wrapper to support CLI-based or address-based mining
Block Blockchain::mineBlock(const std::string &minerAddress) {
    std::cout << "[DEBUG] Entered mineBlock() for: " << minerAddress << "\n";

    if (pendingTransactions.empty()) {
        std::cout << "⚠️ No pending transactions to mine!\n";
        return Block(); // Return empty block
    }

    // Load miner keys from default paths based on address
    std::string dilithiumKeyPath = "/root/.alyncoin/keys/" + minerAddress + "_dilithium.key";
    std::string falconKeyPath    = "/root/.alyncoin/keys/" + minerAddress + "_falcon.key";

    std::cout << "[DEBUG] Checking key file existence...\n";
    if (!Crypto::fileExists(dilithiumKeyPath) || !Crypto::fileExists(falconKeyPath)) {
        std::cerr << "❌ Miner key(s) not found for address: " << minerAddress << "\n";
        return Block();
    }

    std::cout << "[DEBUG] Loading private keys...\n";
    std::vector<unsigned char> dilithiumPriv = Crypto::loadDilithiumKeys(minerAddress).privateKey;
    std::vector<unsigned char> falconPriv    = Crypto::loadFalconKeys(minerAddress).privateKey;

    std::cout << "[DEBUG] Private keys loaded. Lengths: "
              << dilithiumPriv.size() << " (Dilithium), "
              << falconPriv.size() << " (Falcon)\n";

    if (dilithiumPriv.empty() || falconPriv.empty()) {
        std::cerr << "❌ Failed to load Dilithium or Falcon private key for mining!\n";
        return Block();
    }

    std::string minerDilithiumKeyHex = Crypto::toHex(dilithiumPriv);
    std::string minerFalconKeyHex    = Crypto::toHex(falconPriv);

    std::cout << "[DEBUG] Calling minePendingTransactions...\n";
    Block newBlock = minePendingTransactions(minerAddress, dilithiumPriv, falconPriv);

    std::cout << "[DEBUG] Updating transaction history...\n";
    updateTransactionHistory(newBlock.getTransactions().size());

    return newBlock;
}

// ✅ **Fix Smart Burn Mechanism**
int Blockchain::getRecentTransactionCount() {
  if (recentTransactionCounts.empty())
    return 0;

  int sum = 0;
  for (int count : recentTransactionCounts)
    sum += count;

  return sum / recentTransactionCounts.size();
}

// ✅ **Update Transaction History for Dynamic Burn Rate**
void Blockchain::updateTransactionHistory(int newTxCount) {
  if (recentTransactionCounts.size() > 100) {
    recentTransactionCounts.pop_front(); // Keep last 100 blocks' data
  }
  recentTransactionCounts.push_back(newTxCount);
}
// ✅ Get latest block
const Block &Blockchain::getLatestBlock() const {
  if (chain.empty()) {
    std::cerr << "❌ Error: Blockchain is empty! Returning a default block."
              << std::endl;
    static Block defaultBlock(0, "00000000000000000000000000000000", {},
                              "System", 4,
                              std::time(nullptr), // ✅ Added timestamp
                              0                   // ✅ Added nonce
    );
    return defaultBlock;
  }
  return chain.back();
}

// ✅ Get pending transactions
std::vector<Transaction> Blockchain::getPendingTransactions() const {
  return pendingTransactions;
}
//
Json::Value Blockchain::toJSON() const {
  Json::Value json;

  json["chain"] = Json::arrayValue;
  for (const Block &block : chain) {
    json["chain"].append(block.toJSON());
  }

  json["pending_transactions"] = Json::arrayValue;
  for (const Transaction &tx : pendingTransactions) {
    json["pending_transactions"].append(tx.toJSON());
  }

  json["difficulty"] = difficulty;
  json["block_reward"] = blockReward;

  return json;
}

//
void Blockchain::fromJSON(const Json::Value &json) {
  chain.clear();

  for (const auto &blockJson : json["chain"]) {  // ✅ Corrected from "blocks"
    Block block = Block::fromJSON(blockJson);
    chain.push_back(block);
  }

  pendingTransactions.clear();
  for (const auto &txJson : json["pending_transactions"]) {
    Transaction tx = Transaction::fromJSON(txJson);
    pendingTransactions.push_back(tx);
  }

  difficulty = json["difficulty"].asUInt();
  blockReward = json["block_reward"].asDouble();
}


// ✅ Update blockchain from JSON
void Blockchain::updateFromJSON(const std::string &jsonData) {
  try {
    Json::Value root;
    Json::CharReaderBuilder reader;
    std::istringstream stream(jsonData);
    std::string errs;

    if (!Json::parseFromStream(reader, stream, &root, &errs)) {
      std::cerr << "❌ Error parsing blockchain JSON: " << errs << std::endl;
      return;
    }

    fromJSON(root);  // ✅ Delegates to fixed logic

    saveToDB();
    std::cout << "✅ Blockchain updated from JSON!\n";
  } catch (const std::exception &e) {
    std::cerr << "❌ Exception in updateFromJSON: " << e.what() << std::endl;
  }
}

// Store recent transaction counts
std::deque<int> recentTransactionCounts;

// checkDevFundActivity
void Blockchain::checkDevFundActivity() {
  std::time_t currentTime = std::time(nullptr);
  double monthsInactive =
      difftime(currentTime, devFundLastActivity) / (30 * 24 * 60 * 60);

  if (monthsInactive >= 24.0 && !votingSession.isActive) {
    std::cout << "🔔 Dev Fund has been inactive for 24 months. Initiating "
                 "voting session.\n";
    initiateVotingSession();
  } else if (monthsInactive >= 18.0 && monthsInactive < 24.0) {
    std::cout << "⚠️ Dev Fund has been inactive for 18 months. Consider "
                 "initiating voting session.\n";
  }
}
// distributeDevFund
void Blockchain::distributeDevFund() {
  double totalSupply = getTotalSupply();
  std::map<std::string, double> holderShares;

  // Calculate each holder's share
  for (const auto &[address, balance] : balances) {
    if (address != DEV_FUND_ADDRESS) {
      holderShares[address] = balance / totalSupply;
    }
  }

  // Distribute 50% of Dev Fund to holders
  double distributionAmount = devFundBalance * 0.5;
  for (const auto &[address, share] : holderShares) {
    double amount = distributionAmount * share;
    balances[address] += amount;
    std::cout << "Distributed " << amount << " to " << address << "\n";
  }

  // Reserve the remaining 50%
  double reserveAmount = devFundBalance * 0.5;
  balances["Reserve"] += reserveAmount;
  std::cout << "Reserved " << reserveAmount << " to Reserve\n";

  // Reset Dev Fund balance
  devFundBalance = 0.0;
}
// initiateVotingSession
void Blockchain::initiateVotingSession() {
  votingSession.startTime = std::time(nullptr);
  votingSession.isActive = true;
  votingSession.votes.clear();
  std::cout << "Voting session initiated to elect a new Dev Fund holder.\n";
}
// tallyVotes
void Blockchain::tallyVotes() {
  if (!votingSession.isActive) {
    std::cout << "No active voting session.\n";
    return;
  }

  std::string newDevFundAddress;
  double highestVotes = 0.0;

  for (const auto &[address, totalWeight] : votingSession.votes) {
    if (totalWeight > highestVotes) {
      highestVotes = totalWeight;
      newDevFundAddress = address;
    }
  }

  if (!newDevFundAddress.empty()) {
    std::cout << "New Dev Fund holder elected: " << newDevFundAddress << "\n";
    // Transfer Dev Fund balance to the new holder
    balances[newDevFundAddress] += devFundBalance;
    devFundBalance = 0.0;
  } else {
    std::cout << "No votes cast. Dev Fund holder remains unchanged.\n";
  }

  votingSession.isActive = false;
}
// getTotalSupply
double Blockchain::getTotalSupply() const {
  double total = 0.0;
  for (const auto &[address, balance] : balances) {
    total += balance;
  }
  return total;
}

// castVote
bool Blockchain::castVote(const std::string &voterAddress,
                          const std::string &candidateAddress) {
  std::cout << "Casting vote from: " << voterAddress
            << " to: " << candidateAddress << "\n";
  return true;
}
//
void Blockchain::addRollupBlock(const RollupBlock &newRollupBlock) {
  if (isRollupBlockValid(newRollupBlock)) {
    rollupChain.push_back(newRollupBlock);
    std::cout << "[INFO] Rollup block added successfully. Index: "
              << newRollupBlock.getIndex() << std::endl;
  } else {
    std::cerr << "[ERROR] Invalid rollup block. Index: "
              << newRollupBlock.getIndex() << std::endl;
  }
}
//
bool Blockchain::isRollupBlockValid(const RollupBlock &newRollupBlock) const {
  // Validate index continuity
  if (newRollupBlock.getIndex() != rollupChain.size()) {
    std::cerr << "[ERROR] Rollup block index mismatch. Expected: "
              << rollupChain.size() << ", Got: " << newRollupBlock.getIndex()
              << std::endl;
    return false;
  }

  // Validate previous hash
  if (!rollupChain.empty() &&
      newRollupBlock.getPreviousHash() != rollupChain.back().getHash()) {
    std::cerr << "[ERROR] Rollup block previous hash mismatch." << std::endl;
    return false;
  }

  // Validate rollup proof
  std::vector<std::string> txHashes;
  for (const auto &tx : newRollupBlock.getTransactions()) {
    txHashes.push_back(tx.getHash());
  }

  if (!ProofVerifier::verifyRollupProof(newRollupBlock.getRollupProof(),
                                        txHashes,
                                        newRollupBlock.getMerkleRoot())) {
    std::cerr << "[ERROR] Rollup block proof verification failed." << std::endl;
    return false;
  }

  // Additional validations as necessary

  return true;
}

// --- Save Rollup Chain ---
void Blockchain::saveRollupChain() const {
  std::ofstream out(ROLLUP_CHAIN_FILE, std::ios::binary);
  if (!out) {
    std::cerr << "❌ Failed to save rollup chain!\n";
    return;
  }
  for (const auto &block : rollupChain) {
    out.write(reinterpret_cast<const char *>(&block), sizeof(RollupBlock));
  }
  std::cout << "💾 Rollup chain saved successfully.\n";
}

// --- Load Rollup Chain ---
void Blockchain::loadRollupChain() {
  std::ifstream in(ROLLUP_CHAIN_FILE, std::ios::binary);
  if (!in) {
    std::cerr << "⚠️ Rollup chain file not found.\n";
    return;
  }
  RollupBlock block;
  while (in.read(reinterpret_cast<char *>(&block), sizeof(RollupBlock))) {
    rollupChain.push_back(block);
  }
  std::cout << "✅ Rollup chain loaded. Blocks: " << rollupChain.size() << "\n";
}

// --- Merge Rollup Chain ---
void Blockchain::mergeRollupChain(const std::vector<RollupBlock> &newChain) {
  for (const auto &block : newChain) {
    rollupChain.push_back(block);
  }
  std::cout << "🔗 Rollup chain merged. Total blocks: " << rollupChain.size()
            << "\n";
}

// --- Aggregate Off-Chain Transactions ---
std::vector<Transaction>
Blockchain::aggregateOffChainTxs(const std::vector<Transaction> &offChainTxs) {
  std::unordered_map<std::string, double> balanceMap;

  // Sum up amounts per recipient
  for (const auto &tx : offChainTxs) {
    balanceMap[tx.getRecipient()] += tx.getAmount();
  }

  // Create a single transaction per recipient
  std::vector<Transaction> aggregatedTxs;
  for (const auto &[recipient, amount] : balanceMap) {
    Transaction aggTx("Aggregator", recipient, amount, "", "",
                      std::time(nullptr));
    aggregatedTxs.push_back(aggTx);
  }

  return aggregatedTxs;
}
// --- Create Rollup Block ---
Block Blockchain::createRollupBlock(
    const std::vector<Transaction> &offChainTxs) {
  std::vector<Transaction> aggregatedTxs = aggregateOffChainTxs(offChainTxs);

  Block rollupBlock(chain.size(), getLatestBlock().getHash(), aggregatedTxs,
                    "System", difficulty, std::time(nullptr),
                    std::time(nullptr));
  rollupBlock.mineBlock(difficulty);

  std::vector<unsigned char> hashBytes(rollupBlock.getHash().begin(),
                                       rollupBlock.getHash().end());

  std::vector<unsigned char> dummyKey(
      32, 0x01); // Dummy key for demonstration, replace as needed.

  std::vector<unsigned char> rollupSigDilithium =
      Crypto::signWithDilithium(hashBytes, dummyKey);
  std::vector<unsigned char> rollupSigFalcon =
      Crypto::signWithFalcon(hashBytes, dummyKey);

  rollupBlock.setDilithiumSignature(Crypto::toHex(rollupSigDilithium));
  rollupBlock.setFalconSignature(Crypto::toHex(rollupSigFalcon));

  return rollupBlock;
}
// Block reward
double Blockchain::calculateBlockReward() {
    const double maxSupply = 250000000.0; // 250 million cap
    double circulatingSupply = getTotalSupply();

    if (circulatingSupply >= maxSupply) {
        return 0.0;
    }

    // 🔄 1. Supply-based decay (linear)
    double remainingRatio = (maxSupply - circulatingSupply) / maxSupply;
    double baseReward = INITIAL_REWARD * remainingRatio;

    // 🔍 2. Usage boost from tx count (up to +20%)
    double usageFactor = std::min(1.0, getRecentTransactionCount() / 100.0);
    double usageBoost = 0.9 + 0.2 * usageFactor;

    // ⏱️ 3. Block time adjustment
    double avgBlockTime = getAverageBlockTime(10); // Last 10 blocks
    double timeMultiplier = 1.0;

    if (avgBlockTime > 120) {         // If blocks are slow
        timeMultiplier = 1.1;         // Slightly boost reward
    } else if (avgBlockTime < 30) {   // If blocks are too fast
        timeMultiplier = 0.85;        // Suppress reward
    }

    // ⚖️ Final reward (capped min/max)
    double adjustedReward = baseReward * usageBoost * timeMultiplier;
    adjustedReward = std::clamp(adjustedReward, 0.1, 15.0); // Hard cap max

    // 🧮 Prevent going over supply cap
    if (circulatingSupply + adjustedReward > maxSupply) {
        adjustedReward = maxSupply - circulatingSupply;
    }

    return adjustedReward;
}

// adjustDifficulty
void Blockchain::adjustDifficulty() {
  int newDifficulty = LWMA_calculate_difficulty(*this);
  std::cout << "⚙️ Adjusted difficulty from " << difficulty << " → " << newDifficulty << "\n";
  difficulty = newDifficulty;
}
// block time
double Blockchain::getAverageBlockTime(int recentCount) const {
    if (chain.size() < 2) return 60.0; // default 60s estimate

    int count = std::min((int)chain.size() - 1, recentCount);
    double totalTime = 0.0;

    for (int i = chain.size() - count; i < chain.size(); ++i) {
        time_t prev = chain[i - 1].getTimestamp();
        time_t curr = chain[i].getTimestamp();
        totalTime += difftime(curr, prev);
    }

    return totalTime / count;
}

