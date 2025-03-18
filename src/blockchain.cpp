#include "blockchain.h"
#include "blake3.h"
#include "json/json.h"
#include <iomanip>
#include "difficulty.h"
#include <iostream>
#include <fstream>
#include <thread>
#include <chrono>
#include <mutex>
#include "block_reward.h"
#include <algorithm>
#include <atomic>
#include "transaction.h"
#include "crypto_utils.h"
#include <locale>
#include "network.h"
#include <sys/stat.h>
#include <filesystem>
#include "generated/block_protos.pb.h"
#include "generated/blockchain_protos.pb.h"

namespace fs = std::filesystem;
const std::string BLOCKCHAIN_DB_PATH = "/root/.alyncoin/blockchain_db";

// Global mutex for blockchain safety
std::mutex blockchainMutex;
std::atomic<bool> Blockchain::isMining{false};

// ✅ **Constructor: Open RocksDB**
Blockchain::Blockchain(unsigned short port, const std::string& dbPath) : difficulty(4), miningReward(10.0) {
    network = &Network::getInstance(port, this);
    std::cout << "[DEBUG] Initializing Blockchain..." << std::endl;

    std::string dbPathFinal = BLOCKCHAIN_DB_PATH;
    if (!dbPath.empty()) {
        dbPathFinal = dbPath;
        std::cout << "📁 Using custom DB path: " << dbPathFinal << "\n";
    }

    if (!fs::exists(dbPathFinal)) {
        std::cerr << "⚠️ RocksDB directory missing. Creating: " << dbPathFinal << "\n";
        fs::create_directories(dbPathFinal);
    }

    rocksdb::Options options;
    options.create_if_missing = true;
    rocksdb::Status status = rocksdb::DB::Open(options, dbPathFinal, &db);
    if (!status.ok()) {
        std::cerr << "❌ [ERROR] Failed to open RocksDB: " << status.ToString() << std::endl;
        exit(1);
    }

    std::cout << "[DEBUG] Attempting to load blockchain from DB...\n";
    loadFromDB();
    loadVestingInfoFromDB();

    // ✅ Hardcode first 10,000 early supporters with 50% locked for 6 months
    for (int i = 1; i <= 10000; ++i) {
        std::string supporterAddress = "supporter" + std::to_string(i);
        double initialAmount = 10000.0;  // Example initial allocation (adjust as needed)
        addVestingForEarlySupporter(supporterAddress, initialAmount);
    }

    std::cout << "✅ Vesting schedule applied to first 10,000 early supporters.\n";
}

// ✅ **Destructor: Close RocksDB**
Blockchain::~Blockchain() {
    if (db) {
        delete db;
        db = nullptr;  // ✅ Prevent potential use-after-free issues
    }
}

// ✅ **Validate a Transaction**
bool Blockchain::isTransactionValid(const Transaction& tx) const {
    std::string sender = tx.getSender();

    // Skip validation for mining rewards
    if (sender == "System") return true;

    // 🔒 Vesting Check
    auto it = vestingMap.find(sender);
    if (it != vestingMap.end()) {
        double locked = it->second.lockedAmount;
        uint64_t unlockTime = it->second.unlockTimestamp;

        if (std::time(nullptr) < unlockTime) {
            double senderBalance = getBalance(sender);
            if (senderBalance - locked < tx.getAmount()) {
                std::cerr << "⛔ [VESTING] Transaction rejected! Locked balance in effect for: " << sender << "\n";
                return false;
            } else {
                std::cout << "🔓 [VESTING] Allowed: Unlocked balance sufficient for transaction.\n";
            }
        } else {
            std::cout << "✅ [VESTING] Vesting period expired. No restriction.\n";
        }
    }

    // Normalize sender name (replace spaces, avoid case issues)
    std::string normalizedSender = sender;
    std::replace(normalizedSender.begin(), normalizedSender.end(), ' ', '_');

    // Locate public key
    std::string publicKeyPath = getPublicKeyPath(normalizedSender);
    if (!fs::exists(publicKeyPath)) {
        std::cerr << "❌ Public key missing for sender: " << sender << "\n";
        return false;
    }

    // Verify signature
    std::cout << "🔍 [DEBUG] Transaction Hash for Verification: " << tx.calculateHash() << "\n";
    std::cout << "[DEBUG] Public key path used: " << publicKeyPath << "\n";
    if (!Crypto::verifyMessage(publicKeyPath, tx.getSignature(), tx.calculateHash())) {
        std::cerr << "❌ [ERROR] Signature verification failed for transaction from: " << sender << "\n";
        return false;
    }

    std::cout << "✅ [DEBUG] Transaction signature verified successfully for: " << sender << "\n";
    return true;
}

// ✅ Create the Genesis Block Properly
Block Blockchain::createGenesisBlock() {
    std::vector<Transaction> transactions;
    Block genesis(0, "00000000000000000000000000000000", transactions, "System", difficulty, std::time(nullptr), 0);
  std::cout << "[DEBUG] Genesis Block created with hash: " << genesis.getHash() << std::endl;
    std::string keyPath = getPrivateKeyPath("System");
  std::cout << "[DEBUG] Genesis private key path: " << keyPath << std::endl;
    if (!fs::exists(keyPath)) {
        std::cerr << "⚠️ [WARNING] Private key missing for Genesis Block! Generating...\n";
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
bool Blockchain::addBlock(const Block& newBlock) {
    if (chain.empty()) {
        if (!newBlock.isGenesisBlock()) {
            std::cerr << "❌ First block must be the Genesis Block!\n";
            return false;
        }
    } else {
        Block lastBlock = chain.back();
        if (!newBlock.isValid(lastBlock.getHash())) {
            std::cerr << "❌ Invalid block detected. Rejecting!\n";
            return false;
        }
    }

    chain.push_back(newBlock);

    // ✅ Remove included transactions from pendingTransactions
    for (const auto& tx : newBlock.getTransactions()) {
        pendingTransactions.erase(
            std::remove_if(pendingTransactions.begin(), pendingTransactions.end(),
                           [&tx](const Transaction& pendingTx) {
                               return pendingTx.getHash() == tx.getHash();
                           }),
            pendingTransactions.end());
    }

    // ✅ Save blockchain and pending transactions after update
    saveToDB();
    saveTransactionsToDB();

    std::cout << "✅ Block added to blockchain. Pending TXs updated.\n";
    return true;
}
// ✅ Adjust mining difficulty dynamically
void Blockchain::adjustDifficulty() {
    if (chain.size() < 10) return;

    const int difficultyWindow = 10;
    std::vector<uint64_t> timestamps;

    for (int i = chain.size() - difficultyWindow; i < chain.size(); i++) {
        timestamps.push_back(chain[i].getTimestamp());
    }

    if (timestamps.size() < 2) return;

    double avgBlockTime = (timestamps.back() - timestamps.front()) / (difficultyWindow - 1);
    double targetTime = 30.0;  // Target block time

    if (avgBlockTime < targetTime * 0.8) {
        difficulty = std::min(difficulty + 1, 8);
        std::cout << "⚡ Increasing difficulty to: " << difficulty << "\n";
    } else if (avgBlockTime > targetTime * 1.2) {
        difficulty = std::max(difficulty - 1, 4);
        std::cout << "🐢 Reducing difficulty to: " << difficulty << "\n";
    } else {
        std::cout << "✅ Difficulty remains the same: " << difficulty << "\n";
    }
}

// ✅ **Singleton Instance**
Blockchain& Blockchain::getInstance(unsigned short port, const std::string& dbPath) {
    static Blockchain instance(port, dbPath);
    return instance;
}

//
const std::vector<Block>& Blockchain::getChain() const {
    return chain;
}
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

    for (const auto& peer : peers) {
        network->requestBlockchainSync(peer);  // ✅ Pass argument
    }
}

//
void Blockchain::clearPendingTransactions() {
    pendingTransactions.clear();  // ✅ No mutex lock needed

    // ✅ Ensure transactions file is emptied
    std::ofstream outFile("data/transactions.json", std::ios::trunc);
    if (outFile.is_open()) {
        outFile << "[]";  // Empty JSON array
        outFile.close();
    } else {
        std::cerr << "❌ [ERROR] Failed to open transactions.json for clearing!" << std::endl;
    }

    std::cout << "🚨 Cleared all pending transactions after mining.\n";
}

// ✅ Helper function to check if a file exists
bool fileExists(const std::string& filename) {
    struct stat buffer;
    return (stat(filename.c_str(), &buffer) == 0);
}
//
void Blockchain::mergeWith(const Blockchain& other) {
    if (other.chain.size() <= chain.size()) {
        std::cerr << "⚠️ Merge skipped: Local chain is longer or equal.\n";
        return;
    }

    std::vector<Block> newChain;
    for (const auto& block : other.chain) {
        if (newChain.empty() || block.isValid(newChain.back().getHash())) {
            newChain.push_back(block);
        } else {
            std::cerr << "❌ [ERROR] Invalid block detected during merge! Skipping...\n";
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
    return !pendingTransactions.empty();  // ✅ Only checks, does not modify!
}
//
void Blockchain::setPendingTransactions(const std::vector<Transaction>& transactions) {
    pendingTransactions = transactions;
}

// ✅ Mine pending transactions and dynamically adjust difficulty
Block Blockchain::minePendingTransactions(const std::string& minerAddress) {
    std::lock_guard<std::mutex> lock(blockchainMutex);

    if (pendingTransactions.empty()) {
        std::cerr << "⚠️ No transactions to mine!\n";
        return Block();
    }

    std::vector<Transaction> validTransactions;
    for (auto tx : pendingTransactions) {
        if (isTransactionValid(tx)) {
            double originalAmount = tx.getAmount();
            std::string sender = tx.getSender();

            // ✅ Calculate fee (0.1% total)
            double feeRate = 0.001;
            double feeAmount = originalAmount * feeRate;
            double burnFee = feeAmount / 2;
            double devFundFee = feeAmount / 2;
            double adjustedAmount = originalAmount - feeAmount;

            // ✅ Apply Smart Burn (burn rate) additionally
            tx.applyBurn(sender, adjustedAmount, getRecentTransactionCount());
            double smartBurnAmount = tx.getAmount() - adjustedAmount;
            totalBurnedSupply += smartBurnAmount;

            // ✅ Add transaction with adjusted amount (after fee and burn)
            Transaction burnedTx(sender, tx.getRecipient(), adjustedAmount, tx.getSignature());
            validTransactions.push_back(burnedTx);

            // ✅ Create dev fund fee transaction
            Transaction devFeeTx(sender, DEV_FUND_ADDRESS, devFundFee, tx.getSignature());
            validTransactions.push_back(devFeeTx);

            // ✅ Update total burned supply (fee burn + smart burn)
            totalBurnedSupply += burnFee;

            std::cout << "💸 Fee: " << feeAmount << " (Burned: " << burnFee << ", Dev Fund: " << devFundFee << ") from " << sender << "\n";
            std::cout << "🔥 Smart Burn Applied: " << smartBurnAmount << " AlynCoin\n";
        }
    }

    // ✅ Add block reward transaction
    Transaction rewardTx("System", minerAddress, BASE_BLOCK_REWARD, "");
    validTransactions.push_back(rewardTx);

    Block lastBlock = getLatestBlock();
    Block newBlock(chain.size(), lastBlock.getHash(), validTransactions, minerAddress, difficulty, std::time(nullptr), 0);
    newBlock.mineBlock(difficulty);
    addBlock(newBlock);
    clearPendingTransactions();
    saveToDB();

    std::cout << "✅ Block mined. Total burned: " << totalBurnedSupply << " AlynCoin\n";

    return newBlock;
}

// ✅ **Sync Blockchain**
void Blockchain::syncChain(const Json::Value& jsonData) {
    std::lock_guard<std::mutex> lock(blockchainMutex);

    std::vector<Block> newChain;
    for (const auto& blockJson : jsonData["chain"]) {
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
        std::cout << "✅ Blockchain successfully synchronized with a longer chain!\n";
    } else {
        std::cerr << "⚠️ [WARNING] Received chain was not longer. No changes applied.\n";
    }
}

// ✅ **Start Mining**
void Blockchain::startMining(const std::string& minerAddress) {
    if (isMining.load()) {
        std::cout << "⚠️ Mining is already running!" << std::endl;
        return;
    }

    isMining.store(true);

    std::thread([this, minerAddress]() {
        while (isMining.load()) {
            reloadBlockchainState();
            if (pendingTransactions.empty()) {
                std::cout << "⏳ No transactions to mine. Waiting...\n";
                std::this_thread::sleep_for(std::chrono::seconds(5));
                continue;
            }

            Block newBlock = minePendingTransactions(minerAddress);
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
    for (const Block& block : chain) {
        if (seenHashes.find(block.getHash()) != seenHashes.end()) {
            continue;  // Skip duplicate blocks
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
    std::cout << "🔥 Total Burned Supply: " << totalBurnedSupply << " AlynCoin 🔥\n";
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
void Blockchain::addTransaction(const Transaction& tx) {
    std::lock_guard<std::mutex> lock(blockchainMutex);

    // Lowercase sender name
    std::string senderLower = tx.getSender();
    std::transform(senderLower.begin(), senderLower.end(), senderLower.begin(), ::tolower);

    // Check if public key exists, generate if missing
    std::string keyDir = KEY_DIR;
    std::string publicKeyPath = keyDir + senderLower + "_public.pem";

    if (!fs::exists(publicKeyPath)) {
        std::cerr << "⚠️ [WARNING] Public key missing for " << senderLower << "! Generating now...\n";
        Crypto::generateKeysForUser(senderLower);
        std::this_thread::sleep_for(std::chrono::milliseconds(500)); // Small wait to ensure key generation
    }

    // Update balances
    balances[tx.getSender()] -= tx.getAmount();
    balances[tx.getRecipient()] += tx.getAmount();

    // Monitor Dev Fund activity
    if (tx.getSender() == DEV_FUND_ADDRESS || tx.getRecipient() == DEV_FUND_ADDRESS) {
        devFundLastActivity = std::time(nullptr);
        checkDevFundActivity();
    }

    // Add to pending transactions
    pendingTransactions.push_back(tx);
    saveTransactionsToDB();

    std::cout << "✅ Transaction added. Pending count: " << pendingTransactions.size() << "\n";
}

// ✅ **Get balance of a public key**
double Blockchain::getBalance(const std::string& publicKey) const {
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
            std::lock_guard<std::mutex> lock(blockchainMutex);  // ✅ Lock only inside scope
            for (size_t i = 0; i < pendingTransactions.size(); i++) {
             Json::Value txJson = pendingTransactions[i].toJSON();
             txJson["timestamp"] = static_cast<Json::Int64>(pendingTransactions[i].getTimestamp()); // Ensure timestamp
             std::string txData = Json::writeString(writer, txJson);
             batch.Put("tx_" + std::to_string(i), txData);

            }
        }  // ✅ Mutex automatically unlocks

        rocksdb::Status status = db->Write(rocksdb::WriteOptions(), &batch);
        if (!status.ok()) {
            std::cerr << "❌ Error saving transactions to RocksDB: " << status.ToString() << std::endl;
        } else {
            std::cout << "✅ Transactions successfully saved to RocksDB.\n";
        }
    }).detach();  // ✅ Run asynchronously, without blocking the mutex
}

// ✅ **Save Blockchain to RocksDB using Protobuf**
bool Blockchain::saveToDB() {
    std::cout << "[DEBUG] Attempting to save blockchain to DB..." << std::endl;
    if (!db) {
        std::cerr << "❌ RocksDB not initialized!\n";
        return false;
    }

    alyncoin::BlockchainProto blockchainProto;
    for (const auto& block : chain) {
        alyncoin::BlockProto* blockProto = blockchainProto.add_blocks();
        *blockProto = block.toProtobuf();
    }

    std::string serializedData;
    blockchainProto.SerializeToString(&serializedData);

    rocksdb::Status status = db->Put(rocksdb::WriteOptions(), "blockchain", serializedData);

    if (!status.ok()) {
        std::cerr << "❌ [ERROR] Failed to save blockchain: " << status.ToString() << "\n";
        return false;
    }

    // ✅ Save total burned supply
    db->Put(rocksdb::WriteOptions(), "burned_supply", std::to_string(totalBurnedSupply));

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
    rocksdb::Status status = db->Get(rocksdb::ReadOptions(), "blockchain", &serializedBlockchain);
    if (!status.ok()) {
        std::cerr << "⚠️ RocksDB blockchain not found. Creating Genesis Block.\n";
        chain.push_back(createGenesisBlock());
        return saveToDB();
    }

    alyncoin::BlockchainProto blockchainProto;
    if (!blockchainProto.ParseFromString(serializedBlockchain)) {
        std::cerr << "❌ [ERROR] Failed to parse blockchain Protobuf data!\n";
        return false;
    }

    chain.clear();
    for (const auto& blockProto : blockchainProto.blocks()) {
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

    std::cout << "✅ Blockchain loaded successfully!\n";
    return true;
}

// ✅ Save vesting data to DB
void Blockchain::saveVestingInfoToDB() {
    if (!db) return;

    rocksdb::WriteBatch batch;
    for (const auto& pair : vestingMap) {
        std::string key = "vesting_" + pair.first;
        Json::Value vestingJson;
        vestingJson["lockedAmount"] = pair.second.lockedAmount;
        vestingJson["unlockTimestamp"] = static_cast<Json::UInt64>(pair.second.unlockTimestamp);

        Json::StreamWriterBuilder writer;
        std::string data = Json::writeString(writer, vestingJson);
        batch.Put(key, data);
    }
    db->Write(rocksdb::WriteOptions(), &batch);
}

// ✅ Load vesting data from DB
void Blockchain::loadVestingInfoFromDB() {
    if (!db) return;

    rocksdb::Iterator* it = db->NewIterator(rocksdb::ReadOptions());
    for (it->SeekToFirst(); it->Valid(); it->Next()) {
        std::string key = it->key().ToString();
        if (key.find("vesting_") != 0) continue;

        std::string address = key.substr(8);
        Json::Value vestingJson;
        Json::CharReaderBuilder reader;
        std::istringstream stream(it->value().ToString());
        std::string errs;

        if (Json::parseFromStream(reader, stream, &vestingJson, &errs)) {
            VestingInfo info;
            info.lockedAmount = vestingJson["lockedAmount"].asDouble();
            info.unlockTimestamp = vestingJson["unlockTimestamp"].asUInt64();
            vestingMap[address] = info;
        }
    }
    delete it;
}
// vesting
void Blockchain::addVestingForEarlySupporter(const std::string& address, double initialAmount) {
    VestingInfo info;
    info.lockedAmount = initialAmount * 0.5;  // 50% locked
    info.unlockTimestamp = std::time(nullptr) + (6 * 30 * 24 * 60 * 60); // 6 months
    vestingMap[address] = info;
    saveVestingInfoToDB();
    std::cout << "🚀 Vesting applied to early supporter: " << address << "\n";
}

// ✅ Serialize Blockchain to Protobuf
bool Blockchain::serializeBlockchain(std::string& outData) const {
    alyncoin::BlockchainProto blockchainProto;

    for (const auto& block : chain) {
        auto* protoBlock = blockchainProto.add_blocks();
        block.serializeToProtobuf(*protoBlock);
    }

    for (const auto& tx : pendingTransactions) {
        auto* txProto = blockchainProto.add_pending_transactions();
        tx.serializeToProtobuf(*txProto);
    }

    blockchainProto.set_difficulty(difficulty);
    blockchainProto.set_block_reward(blockReward);

    if (!blockchainProto.SerializeToString(&outData)) {
        std::cerr << "❌ [ERROR] Failed to serialize blockchain to Protobuf format!\n";
        return false;
    }

    std::cout << "📡 [DEBUG] Serialized Blockchain Data (Size: " << outData.size() << " bytes)\n";
    std::cout << "📡 [DEBUG] First 100 Bytes of Serialized Data: " << outData.substr(0, 100) << "\n";

    return true;
}

// ✅ Deserialize Blockchain from Protobuf
bool Blockchain::deserializeBlockchain(const std::string& data) {
    std::lock_guard<std::mutex> lock(blockchainMutex);

    if (data.empty()) {
        std::cerr << "❌ [ERROR] Received empty Protobuf blockchain data!\n";
        return false;
    }

    std::cout << "📡 [DEBUG] Received Blockchain Data (Size: " << data.size() << " bytes)\n";
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

    for (const auto& blockProto : protoChain.blocks()) {
        Block block;
        if (!block.deserializeFromProtobuf(blockProto)) {
            std::cerr << "❌ [ERROR] Invalid block format during deserialization!\n";
            return false;
        }
        chain.push_back(block);
    }

    for (const auto& txProto : protoChain.pending_transactions()) {
        Transaction tx;
        if (!tx.deserializeFromProtobuf(txProto)) {
            std::cerr << "❌ [ERROR] Invalid transaction format!\n";
            return false;
        }
        pendingTransactions.push_back(tx);
    }

    std::cout << "✅ Blockchain deserialization completed! Blocks: " << chain.size()
              << ", Pending Transactions: " << pendingTransactions.size() << std::endl;
    return true;
}
//
// ✅ Convert Protobuf back to Block
// ✅ Correct version already in blockchain.cpp:
void Blockchain::fromProto(const alyncoin::BlockchainProto& protoChain) {
    std::lock_guard<std::mutex> lock(blockchainMutex);
    chain.clear();

    for (const auto& protoBlock : protoChain.blocks()) {
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
        for (const auto& protoTx : protoBlock.transactions()) {
            Transaction tx;
            if (tx.deserializeFromProtobuf(protoTx)) {
                transactions.push_back(tx);
            } else {
                std::cerr << "❌ [ERROR] Invalid transaction skipped in block index " << newBlock.getIndex() << "\n";
            }
        }
        newBlock.setTransactions(transactions);

        chain.push_back(newBlock);
    }
}

// ✅ **Replace blockchain if a longer valid chain is found**
void Blockchain::replaceChain(const std::vector<Block>& newChain) {
    std::lock_guard<std::mutex> lock(blockchainMutex);
    if (newChain.size() > chain.size()) {
        chain = newChain;
        saveToDB();
        std::cout << "✅ Blockchain replaced with a longer valid chain!" << std::endl;
    }
}
//
bool Blockchain::isValidNewBlock(const Block& newBlock) {
    if (chain.empty()) {
        std::cerr << "❌ Error: Blockchain is empty. No previous block to compare." << std::endl;
        return false;
    }

    Block lastBlock = getLatestBlock();

    // ✅ Ensure new block references the latest block's hash
    if (newBlock.getPreviousHash() != lastBlock.getHash()) {
        std::cerr << "❌ Invalid block! Previous hash mismatch." << std::endl;
        return false;
    }

    // ✅ Validate Proof-of-Work
    if (!newBlock.hasValidProofOfWork()) {
        std::cerr << "❌ Invalid block! Proof-of-Work check failed." << std::endl;
        return false;
    }

    // ✅ Ensure Keccak Validation is consistent
    std::string computedKeccak = Crypto::keccak256(newBlock.getHash());
    if (computedKeccak != newBlock.keccakHash) {
        std::cerr << "❌ [ERROR] Keccak validation failed! Expected: " << computedKeccak 
                  << " | Found: " << newBlock.keccakHash << std::endl;
        return false;
    }

    // ✅ Validate Block Signature using the correct hash
    std::string minerPublicKey = KEY_DIR + newBlock.getMinerAddress() + "_public.pem";
    std::string hashToVerify = newBlock.getHash();  // ✅ Ensure correct hash is used
    if (!Crypto::verifyMessage(minerPublicKey, newBlock.getBlockSignature(), hashToVerify)) {
        std::cerr << "❌ Block signature verification failed! Rejecting block.\n";
        return false;
    }

    return true;
}

// ✅ **Load Transactions from RocksDB**
void Blockchain::loadTransactionsFromDB() {
    if (!db) {
        std::cerr << "❌ [ERROR] Database not initialized. Cannot load transactions.\n";
        return;
    }

    std::cout << "🔄 [INFO] Loading transactions from RocksDB...\n";

    rocksdb::Iterator* it = db->NewIterator(rocksdb::ReadOptions());
    pendingTransactions.clear();

    for (it->Seek("tx_"); it->Valid() && it->key().starts_with("tx_"); it->Next()) {
        Json::Value txJson;
        Json::CharReaderBuilder reader;
        std::string errs;
        std::istringstream stream(it->value().ToString());

        // ✅ Prevent excessively large transactions
        if (stream.str().size() > 2048) {
            std::cerr << "⚠️ [WARNING] Transaction too large. Possible corruption. Skipping...\n";
            continue;
        }

        if (!Json::parseFromStream(reader, stream, &txJson, &errs)) {
            std::cerr << "❌ [ERROR] Failed to parse transaction JSON for key: " << it->key().ToString() << "! Skipping transaction.\n";
            continue;
        }

        try {
            Transaction tx = Transaction::fromJSON(txJson);
            if (tx.getAmount() > 0 && !tx.getSender().empty() && !tx.getRecipient().empty()) {
                pendingTransactions.push_back(tx);
            } else {
                std::cerr << "⚠️ [WARNING] Invalid transaction detected! Skipping.\n";
            }
        } catch (const std::exception& e) {
            std::cerr << "❌ [ERROR] Exception while parsing transaction: " << e.what() << std::endl;
        }
    }

    delete it;
    std::cout << "✅ Transactions loaded successfully! Pending count: " << pendingTransactions.size() << std::endl;
}

//
std::string Blockchain::signTransaction(const std::string& privateKeyPath, const std::string& message) {
    if (!std::filesystem::exists(privateKeyPath)) {
        std::cerr << "❌ Error: Private key not found at " << privateKeyPath << ".\n";
        
        // ✅ Auto-generate missing private key
        std::cout << "⚠️ Generating missing private key: " << privateKeyPath << "\n";
        Crypto::generateKeysForUser("alice");  // Ensure key generation
        
        std::this_thread::sleep_for(std::chrono::milliseconds(500));  // ✅ Ensure key is ready
    }

    return Crypto::signMessage(privateKeyPath, message, false);
}

// ✅ **Create Block Properly Before Mining**
Block Blockchain::createBlock(const std::string& minerAddress) {
    std::vector<Transaction> validTransactions;

    for (const auto& tx : pendingTransactions) {
        if (isTransactionValid(tx)) {
            validTransactions.push_back(tx);
        }
    }

    Block newBlock(
        chain.size(),
        getLatestBlock().getHash(),
        validTransactions,
        minerAddress,
        difficulty,
        std::time(nullptr),
        0
    );

    return newBlock;
}

// ✅ **Mine Block with BLAKE3 + Keccak**
Block Blockchain::mineBlock(const std::string& minerAddress) {
    std::lock_guard<std::mutex> lock(blockchainMutex);

    if (pendingTransactions.empty()) {
        std::cout << "⚠️ No pending transactions to mine!\n";
        return Block(); // Return empty block
    }

    // Validate transactions
    std::vector<Transaction> validTransactions;
    for (const auto& tx : pendingTransactions) {
        std::string senderKeyPath = "./keys/" + tx.getSender() + "_public.pem";
        if (tx.isValid(senderKeyPath)) {
            validTransactions.push_back(tx);
            std::cout << "✅ Valid transaction from: " << tx.getSender() << "\n";
        } else {
            std::cout << "❌ Invalid transaction! Skipping...\n";
        }
    }

    if (validTransactions.empty()) {
        std::cout << "⚠️ No valid transactions to mine!\n";
        return Block();
    }

    int difficulty = LWMA_calculate_difficulty(*this);
    Block latest = getLatestBlock();

    // Prepare full block (7 arguments)
    Block newBlock(
        latest.getIndex() + 1,
        latest.getHash(),
        validTransactions,
        minerAddress,
        difficulty,
        std::time(nullptr),
        0
    );

    std::cout << "⏳ Mining block...\n";
    newBlock.mineBlock(difficulty);

    if (newBlock.isValid(latest.getHash())) {
        chain.push_back(newBlock);
        pendingTransactions.clear();
        saveToDB();  // Use your existing DB function
        saveTransactionsToDB(); // Save empty pending txs
        std::cout << "✅ Block mined and added to chain!\n";
        return newBlock;
    } else {
        std::cout << "❌ Mined block failed validation!\n";
        return Block();
    }
}

// ✅ **Fix Smart Burn Mechanism**
int Blockchain::getRecentTransactionCount() {
    if (recentTransactionCounts.empty()) return 0;

    int sum = 0;
    for (int count : recentTransactionCounts) sum += count;

    return sum / recentTransactionCounts.size();
}

// ✅ **Update Transaction History for Dynamic Burn Rate**
void Blockchain::updateTransactionHistory(int newTxCount) {
    if (recentTransactionCounts.size() > 100) {
        recentTransactionCounts.pop_front();  // Keep last 100 blocks' data
    }
    recentTransactionCounts.push_back(newTxCount);
}
// ✅ Get latest block
const Block& Blockchain::getLatestBlock() const {
    if (chain.empty()) {
        std::cerr << "❌ Error: Blockchain is empty! Returning a default block." << std::endl;
        static Block defaultBlock(
            0,
            "00000000000000000000000000000000",
            {},
            "System",
            4,
            std::time(nullptr),  // ✅ Added timestamp
            0  // ✅ Added nonce
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
    json["chain"] = Json::arrayValue; // Create an array for blocks

    for (const Block& block : chain) {  // Assuming `chain` is the vector storing blocks
        json["chain"].append(block.toJSON()); // Call `Block::toJSON()`
    }

    json["pending_transactions"] = Json::arrayValue;
    for (const Transaction& tx : pendingTransactions) { // Assuming `pendingTransactions` exists
        json["pending_transactions"].append(tx.toJSON()); // Call `Transaction::toJSON()`
    }

    json["difficulty"] = difficulty;
    json["block_reward"] = blockReward;

    return json;
}
//
void Blockchain::fromJSON(const Json::Value& json) {
    chain.clear();
    for (const auto& blockJson : json["blocks"]) {
        Block block;
        block.fromJSON(blockJson);
        chain.push_back(block);
    }

    difficulty = json["difficulty"].asUInt();
    blockReward = json["blockReward"].asDouble();
}

// ✅ Update blockchain from JSON
void Blockchain::updateFromJSON(const std::string& jsonData) {
    try {
        Json::Value root;
        Json::CharReaderBuilder reader;
        std::istringstream stream(jsonData);
        std::string errs;

        if (!Json::parseFromStream(reader, stream, &root, &errs)) {
            std::cerr << "❌ Error parsing blockchain JSON: " << errs << std::endl;
            return;
        }

        chain.clear();
        for (const auto& blockJson : root["chain"]) {
            Block newBlock;
           newBlock = Block::fromJSON(blockJson);
           chain.push_back(newBlock);
        }

        saveToDB();
        std::cout << "✅ Blockchain updated from JSON!\n";
    } catch (const std::exception& e) {
        std::cerr << "❌ Exception in updateFromJSON: " << e.what() << std::endl;
    }
}
// Store recent transaction counts
std::deque<int> recentTransactionCounts;

// checkDevFundActivity
void Blockchain::checkDevFundActivity() {
    std::time_t currentTime = std::time(nullptr);
    double monthsInactive = difftime(currentTime, devFundLastActivity) / (30 * 24 * 60 * 60);

    if (monthsInactive >= 24.0 && !votingSession.isActive) {
        std::cout << "🔔 Dev Fund has been inactive for 24 months. Initiating voting session.\n";
        initiateVotingSession();
    } else if (monthsInactive >= 18.0 && monthsInactive < 24.0) {
        std::cout << "⚠️ Dev Fund has been inactive for 18 months. Consider initiating voting session.\n";
    }
}
// distributeDevFund
void Blockchain::distributeDevFund() {
    double totalSupply = getTotalSupply();
    std::map<std::string, double> holderShares;

    // Calculate each holder's share
    for (const auto& [address, balance] : balances) {
        if (address != DEV_FUND_ADDRESS) {
            holderShares[address] = balance / totalSupply;
        }
    }

    // Distribute 50% of Dev Fund to holders
    double distributionAmount = devFundBalance * 0.5;
    for (const auto& [address, share] : holderShares) {
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
//initiateVotingSession
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

    for (const auto& [address, totalWeight] : votingSession.votes) {
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
//getTotalSupply
double Blockchain::getTotalSupply() const {
    double total = 0.0;
    for (const auto& [address, balance] : balances) {
        total += balance;
    }
    return total;
}

// castVote
bool Blockchain::castVote(const std::string& voterAddress, const std::string& candidateAddress) {
    if (!votingSession.isActive) {
        std::cout << "No active voting session.\n";
        return false;
    }

    double voterBalance
::contentReference[oaicite:0]{index=0}
 

