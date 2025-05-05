#include "generated/block_protos.pb.h"
#include "generated/blockchain_protos.pb.h"
#include "blockchain.h"
#include "blake3.h"
#include "difficulty.h"
#include "block_reward.h"
#include "crypto_utils.h"
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
#include "db/db_paths.h"
#include <locale>
#include <mutex>
#include <sys/stat.h>
#include <thread>
#include "logger.h"

#define ROLLUP_CHAIN_FILE "rollup_chain.dat"
static std::map<uint64_t, Block> futureBlocks;
namespace fs = std::filesystem;
const std::string BLOCKCHAIN_DB_PATH = DBPaths::getBlockchainDB();
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
Blockchain::Blockchain(unsigned short port, const std::string &dbPath, bool bindNetwork, bool isSyncMode)
    : difficulty(4), miningReward(10.0), port(port), dbPath(dbPath) {

    if (bindNetwork) {
        if (Network::isUninitialized()) {
            std::cerr << "❌ [FATAL] Cannot initialize Network without PeerBlacklist!\n";
            throw std::runtime_error("PeerBlacklist is null");
        } else {
            std::cerr << "⚠️ Warning: Network already initialized. Using existing instance.\n";
            network = Network::getExistingInstance();
        }
    } else {
        network = nullptr;
    }

    std::cout << "[DEBUG] Initializing Blockchain..." << std::endl;

    if (dbPath.empty()) {
        std::cerr << "⚠️ Skipping RocksDB init (empty dbPath, --nodb mode).\n";
        db = nullptr;
        return;
    }

    std::string dbPathFinal = dbPath;
    std::cout << "📁 Using custom DB path: " << dbPathFinal << "\n";

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
    bool found = loadFromDB();

    if (!found && !isSyncMode) {
        std::cout << "📐 Creating Genesis Block...\n";
        Block genesis = createGenesisBlock();  // Already adds the block
        std::cout << "[DEBUG] ♻️ Genesis zkProof size in chain.front(): "
                  << genesis.getZkProof().size() << " bytes\n";
        saveToDB();  // ✅ Persist genesis block with correct proof
    } else if (!found) {
        std::cout << "⏳ [INFO] Skipping genesis block — awaiting peer sync...\n";
    }

    recalculateBalancesFromChain();
    loadVestingInfoFromDB();

    std::string vestingMarker;
    status = db->Get(rocksdb::ReadOptions(), "vesting_initialized", &vestingMarker);

    if (!status.ok()) {
        std::cout << "⏳ Applying vesting schedule for early supporters...\n";
        applyVestingSchedule();
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
        std::string canonicalHash = tx.getTransactionHash();  // ✅ Use canonical hash
        std::vector<unsigned char> hashBytes = Crypto::fromHex(canonicalHash);
        std::vector<unsigned char> sigDilithium = Crypto::fromHex(tx.getSignatureDilithium());
        std::vector<unsigned char> sigFalcon = Crypto::fromHex(tx.getSignatureFalcon());
        std::vector<unsigned char> pubKeyDilithium = Crypto::fromHex(tx.getSenderPublicKeyDilithium());
        std::vector<unsigned char> pubKeyFalcon = Crypto::fromHex(tx.getSenderPublicKeyFalcon());

        std::cout << "[DEBUG] Verifying TX: " << canonicalHash << "\n";
        std::cout << "  - Sender: " << sender << "\n";
        std::cout << "  - Amount: " << tx.getAmount() << "\n";
        std::cout << "  - zkProof Size: " << tx.getZkProof().size() << " bytes\n";

        if (!Crypto::verifyWithDilithium(hashBytes, sigDilithium, pubKeyDilithium)) {
            std::cerr << "[ERROR] Dilithium signature verification failed!\n";
            return false;
        }

        if (!Crypto::verifyWithFalcon(hashBytes, sigFalcon, pubKeyFalcon)) {
            std::cerr << "[ERROR] Falcon signature verification failed!\n";
            return false;
        }

        if (tx.getZkProof().empty()) {
            std::cerr << "[ERROR] Transaction missing zk-STARK proof!\n";
            return false;
        }

        if (!WinterfellStark::verifyTransactionProof(tx.getZkProof(), sender, tx.getRecipient(), tx.getAmount(), tx.getTimestamp())) {
            std::cerr << "[ERROR] zk-STARK proof verification failed!\n";
            return false;
        }

    } catch (const std::exception &e) {
        std::cerr << "❌ Exception during isTransactionValid: " << e.what() << "\n";
        return false;
    }

    std::cout << "✅ Transaction verified successfully for: " << sender << "\n";
    return true;
}

// ✅ Create the Genesis Block Properly
Block Blockchain::createGenesisBlock(bool force) {
    if (!force && !chain.empty()) {
        std::cerr << "⚠️ Genesis block already exists. Skipping creation.\n";
        return chain.front();
    }

    std::vector<Transaction> transactions;
    std::string prevHash = "00000000000000000000000000000000";
    std::string creator = "System";
    uint64_t fixedTimestamp = 1713120000;

    Block genesis(0, prevHash, transactions, creator, difficulty, fixedTimestamp, 0);

    std::string txRoot = genesis.computeTransactionsHash();
    genesis.setTransactionsHash(txRoot);
    genesis.setMerkleRoot(txRoot);

    std::string blockHash = genesis.calculateHash();
    genesis.setHash(blockHash);
    std::cout << "[DEBUG] Genesis Block created with hash: " << blockHash << std::endl;

    std::string rsaKeyPath = getPrivateKeyPath("System");
    if (!fs::exists(rsaKeyPath)) {
        std::cerr << "⚠️ RSA key missing for Genesis. Generating...\n";
        Crypto::generateKeysForUser("System");
    }

    std::string rsaSig = Crypto::signMessage(blockHash, rsaKeyPath, true);
    if (rsaSig.empty()) {
        std::cerr << "❌ RSA signature failed!\n";
        exit(1);
    }
    genesis.setSignature(rsaSig);

    auto dilKeys = Crypto::loadDilithiumKeys("System");
    auto falKeys = Crypto::loadFalconKeys("System");

    if (dilKeys.privateKey.empty() || falKeys.privateKey.empty()) {
        std::cerr << "⚠️ PQ keys missing. Regenerating...\n";
        Crypto::generatePostQuantumKeys("System");
        dilKeys = Crypto::loadDilithiumKeys("System");
        falKeys = Crypto::loadFalconKeys("System");
    }

    std::vector<unsigned char> msgBytes = genesis.getSignatureMessage();
    if (msgBytes.size() != 32) {
        std::cerr << "❌ Message must be 32 bytes!\n";
        exit(1);
    }

    auto sigDilVec = Crypto::signWithDilithium(msgBytes, dilKeys.privateKey);
    auto sigFalVec = Crypto::signWithFalcon(msgBytes, falKeys.privateKey);
    if (sigDilVec.empty() || sigFalVec.empty()) {
        std::cerr << "❌ PQ signature failed!\n";
        exit(1);
    }

    genesis.setDilithiumSignature(sigDilVec);
    genesis.setFalconSignature(sigFalVec);

    // ✅ Validate and set public keys
    if (dilKeys.publicKey.size() != DILITHIUM_PUBLIC_KEY_BYTES) {
        std::cerr << "❌ Dilithium public key size invalid: " << dilKeys.publicKey.size()
                 << " (expected: " << DILITHIUM_PUBLIC_KEY_BYTES << ")\n";
        exit(1);
    }
    genesis.setPublicKeyDilithium(dilKeys.publicKey);

    if (falKeys.publicKey.size() != FALCON_PUBLIC_KEY_BYTES) {
        std::cerr << "❌ Falcon public key size invalid: " << falKeys.publicKey.size()
                  << " (expected: " << FALCON_PUBLIC_KEY_BYTES << ")\n";
        exit(1);
    }
    genesis.setPublicKeyFalcon(falKeys.publicKey);

    std::string zkProof = WinterfellStark::generateProof(
        genesis.getHash(),
        genesis.getPreviousHash(),
        genesis.getTransactionsHash()
    );

    std::cout << "[GENESIS] 🔐 Generating zk-STARK proof for Genesis block\n";
    std::cout << "  - Hash        : " << genesis.getHash() << "\n";
    std::cout << "  - PrevHash    : " << genesis.getPreviousHash() << "\n";
    std::cout << "  - TxRoot      : " << genesis.getTransactionsHash() << "\n";
    std::cout << "  - ZK Proof len: " << zkProof.size() << " bytes\n";

    if (zkProof.empty() || zkProof.size() < 64) {
        std::cerr << "❌ zk-STARK proof generation failed for Genesis block!\n";
        exit(1);
    }

    genesis.setZkProof(std::vector<uint8_t>(zkProof.begin(), zkProof.end()));
    std::cout << "[DEBUG] ✅ zkProof set for genesis: " << genesis.getZkProof().size() << " bytes\n";

    std::cout << "[DEBUG] Genesis zkProof size before addBlock: " << genesis.getZkProof().size() << "\n";
    if (!addBlock(genesis)) {
        std::cerr << "❌ Failed to add genesis block!\n";
        exit(1);
    }

    return chain.front();
}

// ✅ Adds block, applies smart burn, and broadcasts to peers
bool Blockchain::addBlock(const Block &block) {
    if (block.getZkProof().empty()) {
        std::cerr << "❌ [ERROR] Cannot add block with EMPTY zkProof! Block Hash: "
                  << block.getHash() << "\n";
        return false;
    } else {
        std::cout << "[DEBUG] 🧩 addBlock() zkProof length: " << block.getZkProof().size() << " bytes\n";
    }

    for (const auto &existing : chain) {
        if (existing.getHash() == block.getHash()) {
            std::cerr << "⚠️ Duplicate block hash detected. Skipping add. Hash: "
                      << block.getHash() << "\n";
            return true;
        }
        if (existing.getIndex() == block.getIndex()) {
            std::cerr << "⚠️ Block index already exists (Index: " << block.getIndex()
                      << "). Skipping add.\n";
            return false;
        }
    }

    if (!chain.empty() && block.getIndex() > chain.back().getIndex() + 1) {
        std::cerr << "⚠️ [Node] Received future block. Index: " << block.getIndex()
                  << ", Expected: " << (chain.back().getIndex() + 1) << ". Buffering.\n";
        futureBlocks[block.getIndex()] = block;
        return false;
    }

    if (block.isGenesisBlock()) {
        std::cout << "🪐 [GENESIS] Adding genesis block without PoW check.\n";
    } else if (!block.hasValidProofOfWork()) {
        std::cerr << "❌ Invalid PoW! Block hash " << block.getHash()
                  << " does not meet difficulty " << block.getDifficulty() << "\n";
        return false;
    }

    if (!isValidNewBlock(block)) {
        std::cerr << "❌ Invalid block detected. Rejecting!\n";
        return false;
    }

    if (block.getDilithiumSignature().empty() || block.getFalconSignature().empty()) {
        std::cerr << "❌ [ERROR] Block missing signature(s). Rejecting.\n";
        return false;
    }
    if (block.getPublicKeyDilithium().empty() || block.getPublicKeyFalcon().empty()) {
        std::cerr << "❌ [ERROR] Block missing public key(s). Rejecting.\n";
        return false;
    }

    // ✅ Validate expected key lengths
    if (block.getPublicKeyFalcon().size() != FALCON_PUBLIC_KEY_BYTES) {
        std::cerr << "❌ [ERROR] Falcon public key length mismatch. Got: "
                  << block.getPublicKeyFalcon().size()
                  << ", Expected: " << FALCON_PUBLIC_KEY_BYTES << "\n";
        return false;
    }

    // Keep older checks for Dilithium min lengths
    if (block.getDilithiumSignature().size() < 500 || block.getPublicKeyDilithium().size() < 400) {
        std::cerr << "❌ [ERROR] Dilithium signature or public key too small. Rejecting.\n";
        return false;
    }
    if (block.getFalconSignature().size() < 400) {
        std::cerr << "❌ [ERROR] Falcon signature too small. Rejecting.\n";
        return false;
    }

    std::cerr << "🧪 [addBlock] Safe push diagnostics:\n";
    std::cerr << "  - Index: " << block.getIndex() << "\n";
    std::cerr << "  - Hash: " << block.getHash() << " (" << block.getHash().size() << " bytes)\n";
    std::cerr << "  - zkProof: " << block.getZkProof().size() << "\n";
    std::cerr << "  - Dilithium Sig: " << block.getDilithiumSignature().size() << "\n";
    std::cerr << "  - Falcon Sig: " << block.getFalconSignature().size() << "\n";
    std::cerr << "  - Dilithium PK: " << block.getPublicKeyDilithium().size() << "\n";
    std::cerr << "  - Falcon PK: " << block.getPublicKeyFalcon().size() << "\n";

    try {
        chain.push_back(block);
    } catch (const std::exception& e) {
        std::cerr << "❌ [CRITICAL] push_back failed: " << e.what() << "\n";
        return false;
    } catch (...) {
        std::cerr << "❌ [CRITICAL] push_back triggered unknown fatal error.\n";
        return false;
    }

    if (chain.back().getHash() != block.getHash()) {
        std::cerr << "❌ [ERROR] After push_back, block hash mismatch. Possible memory error.\n";
        return false;
    }

    if (!block.getTransactions().empty()) {
        for (const auto &tx : block.getTransactions()) {
            pendingTransactions.erase(
                std::remove_if(pendingTransactions.begin(), pendingTransactions.end(),
                               [&tx](const Transaction &pendingTx) {
                                   return pendingTx.getHash() == tx.getHash();
                               }),
                pendingTransactions.end());
        }
    }

    if (db) {
        alyncoin::BlockProto protoBlock = block.toProtobuf();
        std::string serializedBlock;
        if (!protoBlock.SerializeToString(&serializedBlock)) {
            std::cerr << "❌ Failed to serialize block using Protobuf.\n";
            return false;
        }

        std::string blockKeyByHeight = "block_height_" + std::to_string(block.getIndex());
        rocksdb::Status statusHeight = db->Put(rocksdb::WriteOptions(), blockKeyByHeight, serializedBlock);
        if (!statusHeight.ok()) {
            std::cerr << "❌ Failed to save block by height: " << statusHeight.ToString() << "\n";
            return false;
        }

        std::string blockKeyByHash = "block_" + block.getHash();
        rocksdb::Status statusHash = db->Put(rocksdb::WriteOptions(), blockKeyByHash, serializedBlock);
        if (!statusHash.ok()) {
            std::cerr << "❌ Failed to save block by hash: " << statusHash.ToString() << "\n";
            return false;
        }

        if (!saveToDB()) {
            std::cerr << "❌ Failed to save blockchain to database after adding block.\n";
            return false;
        }
    } else {
        std::cerr << "⚠️ Skipped RocksDB writes: DB not initialized (--nodb mode).\n";
    }

    recalculateBalancesFromChain();
    validateChainContinuity();

    std::cout << "✅ Block added to blockchain. Pending transactions updated and balances recalculated.\n";

    uint64_t nextIndex = chain.back().getIndex() + 1;
    while (futureBlocks.count(nextIndex)) {
        Block buffered = futureBlocks[nextIndex];
        futureBlocks.erase(nextIndex);
        std::cout << "📦 Applying buffered future block index: " << nextIndex << "\n";
        addBlock(buffered);
        nextIndex++;
    }

    return true;
}

//
bool Blockchain::forceAddBlock(const Block& block) {
    std::cerr << "🛠️ [forceAddBlock] Forcing block insertion. Index: " << block.getIndex()
              << ", Hash: " << block.getHash() << "\n";

    if (block.getHash().empty()) {
        std::cerr << "❌ [forceAddBlock] Block hash is empty.\n";
        return false;
    }
    if (block.getZkProof().empty()) {
        std::cerr << "❌ [forceAddBlock] zkProof is empty. Unsafe to add.\n";
        return false;
    }
    if (block.getDilithiumSignature().empty() || block.getFalconSignature().empty()) {
        std::cerr << "❌ [forceAddBlock] Block missing signatures.\n";
        return false;
    }

    // ✅ Optional key length check
    if (block.getPublicKeyFalcon().size() != FALCON_PUBLIC_KEY_BYTES) {
        std::cerr << "❌ [forceAddBlock] Falcon public key length mismatch. Got: "
                  << block.getPublicKeyFalcon().size() << ", Expected: "
                  << FALCON_PUBLIC_KEY_BYTES << "\n";
        return false;
    }

    try {
        chain.push_back(block);
    } catch (const std::exception& e) {
        std::cerr << "❌ [forceAddBlock] push_back failed: " << e.what() << "\n";
        return false;
    } catch (...) {
        std::cerr << "❌ [forceAddBlock] push_back triggered unknown exception.\n";
        return false;
    }

    if (db) {
        alyncoin::BlockProto protoBlock = block.toProtobuf();
        std::string serializedBlock;
        if (!protoBlock.SerializeToString(&serializedBlock)) {
            std::cerr << "❌ Failed to serialize block during force add.\n";
            return false;
        }

        std::string blockKeyByHeight = "block_height_" + std::to_string(block.getIndex());
        rocksdb::Status statusHeight = db->Put(rocksdb::WriteOptions(), blockKeyByHeight, serializedBlock);
        if (!statusHeight.ok()) {
            std::cerr << "❌ Failed to save block by height during force add: " << statusHeight.ToString() << "\n";
            return false;
        }

        std::string blockKeyByHash = "block_" + block.getHash();
        rocksdb::Status statusHash = db->Put(rocksdb::WriteOptions(), blockKeyByHash, serializedBlock);
        if (!statusHash.ok()) {
            std::cerr << "❌ Failed to save block by hash during force add: " << statusHash.ToString() << "\n";
            return false;
        }
    } else {
        std::cerr << "⚠️ [forceAddBlock] RocksDB disabled. Block only added in memory.\n";
    }

    std::cout << "✅ [forceAddBlock] Block forced into chain successfully.\n";
    return true;
}

// ✅ Singleton Instance (network + db)
Blockchain &Blockchain::getInstance(unsigned short port, const std::string &dbPath, bool bindNetwork, bool isSyncMode) {
    static Blockchain instance(port, dbPath, bindNetwork, isSyncMode);
    return instance;
}
// ✅ Used when you want RocksDB, but no P2P
Blockchain& Blockchain::getInstanceNoNetwork() {
    static Blockchain instance(0, DBPaths::getBlockchainDB(), false);
    return instance;
}

// ✅ Used when you want NO RocksDB or network
Blockchain& Blockchain::getInstanceNoDB() {
    static Blockchain instance(0, "", false);
    return instance;
}
//
Blockchain& Blockchain::getActiveInstance() {
    return getInstance(DEFAULT_PORT, DBPaths::getBlockchainDB(), true, false);
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
    // Clear in-memory pending transactions
    pendingTransactions.clear();
    std::cout << "🚨 Cleared all pending transactions after mining.\n";

    // Also clear any local JSON file
    if (!std::filesystem::exists("data")) {
        std::filesystem::create_directory("data");
    }
    std::ofstream outFile("data/transactions.json", std::ios::trunc);
    if (outFile.is_open()) {
        outFile << "[]"; // Write empty JSON array
        outFile.close();
    } else {
        std::cerr << "❌ [ERROR] Failed to open transactions.json for clearing!\n";
    }

    // Clear RocksDB entries starting with "tx_"
    if (db) {
        rocksdb::WriteBatch batch;
        rocksdb::Iterator* it = db->NewIterator(rocksdb::ReadOptions());
        int deletedCount = 0;

        for (it->SeekToFirst(); it->Valid(); it->Next()) {
            std::string key = it->key().ToString();
            if (key.rfind("tx_", 0) == 0) {
                batch.Delete(key);
                ++deletedCount;
            }
        }
        delete it;

        if (deletedCount > 0) {
            db->Write(rocksdb::WriteOptions(), &batch);
            std::cout << "🗑️ [TXDB] Deleted old pending TX entries: " << deletedCount << "\n";
        } else {
            std::cout << "✅ [TXDB] No pending TX entries found to delete.\n";
        }
    }
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
    for (size_t i = 0; i < other.chain.size(); ++i) {
        const Block &block = other.chain[i];

        std::string expectedPrevHash = (i == 0)
            ? "00000000000000000000000000000000"
            : newChain.back().getHash();

        if (block.getPreviousHash() != expectedPrevHash) {
            std::cerr << "❌ [ERROR] Invalid previous hash at block index " << block.getIndex()
                      << ". Expected: " << expectedPrevHash << ", Got: " << block.getPreviousHash() << "\n";
            return;
        }

        if (block.getHash() != block.calculateHash()) {
            std::cerr << "❌ [ERROR] Block hash mismatch at index " << block.getIndex() << "\n";
            return;
        }

        // ✅ Skip static difficulty validation (LWMA adjusts on mining only)
        newChain.push_back(block);
    }

    if (newChain.size() > chain.size()) {
        std::cout << "✅ Replacing current blockchain with a longer valid chain!\n";
        chain = newChain;
        adjustDifficulty();  // Recalculate based on new chain via LWMA
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
Block Blockchain::minePendingTransactions(
    const std::string &minerAddress,
    const std::vector<unsigned char> &minerDilithiumPriv,
    const std::vector<unsigned char> &minerFalconPriv)
{
    std::cout << "[DEBUG] Waiting on blockchainMutex in minePendingTransactions()...\n";
    std::lock_guard<std::mutex> lock(blockchainMutex);
    std::cout << "[DEBUG] Acquired blockchainMutex in minePendingTransactions()!\n";

    std::map<std::string, double> tempBalances;
    std::vector<Transaction> validTx;
    std::cout << "[DEBUG] Validating and preparing transactions...\n";

    for (const auto &tx : pendingTransactions) {
        // Ensure serialization validity as well as cryptographic validity
        if (!isTransactionValid(tx) ||
            tx.getSender().empty() ||
            tx.getRecipient().empty() ||
            tx.getAmount() <= 0.0 ||
            tx.getSignatureDilithium().empty() ||
            tx.getSignatureFalcon().empty() ||
            tx.getZkProof().empty()) {
            std::cerr << "❌ Skipping invalid transaction.\n";
            continue;
        }

        std::string sender = tx.getSender();
        double amount = tx.getAmount();
        double senderBal = calculateBalance(sender, tempBalances);

        if (sender != "System" && senderBal < amount) {
            std::cerr << "❌ Insufficient balance (" << senderBal << ") for sender (" << sender << ")\n";
            continue;
        }

        // Fee logic
        double txActivity = static_cast<double>(getRecentTransactionCount());
        double burnRate   = std::clamp(txActivity / 1000.0, 0.01, 0.05);
        double rawFee     = amount * 0.01;
        double maxFeePct  = 0.00005;
        double feeAmount  = std::min({ rawFee, amount * maxFeePct, 1.0 });
        double burnAmount = std::min(feeAmount * burnRate, 0.003);
        double devFundAmt = std::min(feeAmount - burnAmount, 0.002);
        double finalAmount = amount - feeAmount;

        tempBalances[sender] -= amount;
        tempBalances[tx.getRecipient()] += finalAmount;
        tempBalances[DEV_FUND_ADDRESS]  += devFundAmt;
        totalBurnedSupply += burnAmount;

        validTx.push_back(tx); // Fully valid tx

        Transaction devTx = Transaction::createSystemRewardTransaction(DEV_FUND_ADDRESS, devFundAmt);
        if (!devTx.getRecipient().empty() && devFundAmt > 0.0) {
            validTx.push_back(devTx);
        } else {
            std::cerr << "⚠️ Skipped dev fund tx (invalid or zero amount).\n";
        }

        std::cout << "🔥 Burned: " << burnAmount << " AlynCoin"
                  << ", 💰 Dev Fund: " << devFundAmt << " AlynCoin"
                  << ", 📤 Final Sent: " << finalAmount << " AlynCoin\n";
    }

    if (validTx.empty()) {
        std::cout << "⛏️ No valid transactions found, creating empty block.\n";
    }

    // Block reward logic
    double blockRewardVal = 0.0;
    if (totalSupply < MAX_SUPPLY) {
        blockRewardVal = calculateBlockReward();
        if (totalSupply + blockRewardVal > MAX_SUPPLY) {
            blockRewardVal = MAX_SUPPLY - totalSupply;
        }

        Transaction rewardTx = Transaction::createSystemRewardTransaction(minerAddress, blockRewardVal);
        if (!rewardTx.getRecipient().empty() && blockRewardVal > 0.0) {
            validTx.push_back(rewardTx);
            totalSupply += blockRewardVal;
            std::cout << "⛏️ Block reward: " << blockRewardVal << " AlynCoin\n";
        } else {
            std::cerr << "⚠️ Skipped block reward tx (invalid or zero).\n";
        }
    } else {
        std::cerr << "🚫 Block reward skipped. Max supply reached.\n";
    }

    Block lastBlock = getLatestBlock();
    std::cout << "[DEBUG] Last block hash: " << lastBlock.getHash() << "\n";
    adjustDifficulty();
    std::cout << "⚙️ Difficulty set to: " << difficulty << "\n";

    Block newBlock(
        chain.size(),
        lastBlock.getHash(),
        validTx,
        minerAddress,
        difficulty,
        std::time(nullptr),
        0
    );
    newBlock.setReward(blockRewardVal);

    if (!newBlock.mineBlock(difficulty)) {
        std::cerr << "❌ Mining process returned false!\n";
        return Block();
    }

    if (newBlock.getZkProof().empty()) {
        std::cerr << "❌ [ERROR] Mined block has empty zkProof! Aborting mining.\n";
        return Block();
    }

    std::cout << "[DEBUG] Attempting to addBlock()...\n";
    if (!addBlock(newBlock)) {
        std::cerr << "❌ Error adding mined block to blockchain.\n";
        return Block();
    }

    clearPendingTransactions();
    saveToDB();

    std::thread([](Block blockCopy) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        Network::getInstance().broadcastBlock(blockCopy);
    }, newBlock).detach();

    std::cout << "✅ Block mined and added successfully. Total burned supply: " << totalBurnedSupply << "\n";
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

        // ✅ Use fromProto() constructor directly
        Block newBlock = Block::fromProto(protoBlock);
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
void Blockchain::startMining(const std::string &minerAddress,
                             const std::string &minerDilithiumKey,
                             const std::string &minerFalconKey)
{
    // If already mining, do nothing
    if (isMining.load()) {
        std::cout << "⚠️ Mining is already running!\n";
        return;
    }
    isMining.store(true);

    // Convert the hex-encoded private keys once, outside the loop
    std::vector<unsigned char> dilithiumPriv = Crypto::fromHex(minerDilithiumKey);
    std::vector<unsigned char> falconPriv    = Crypto::fromHex(minerFalconKey);

    std::thread([this, minerAddress, dilithiumPriv, falconPriv]() {
        std::cout << "⛏️ Starting continuous mining for: " << minerAddress << "\n";

        while (isMining.load()) {
            // Reload chain & pending TX from DB so we see the latest state
            reloadBlockchainState();

            // ❌ No more “if (pendingTransactions.empty()) { … }” check!
            // We always call minePendingTransactions.

            Block newBlock = minePendingTransactions(minerAddress, dilithiumPriv, falconPriv);

            // If minePendingTransactions returns an empty Block (hash == ""),
            // handle it gracefully or continue
            if (newBlock.getHash().empty()) {
                std::cerr << "⚠️ No block was mined. Possibly no valid transactions.\n";
            } else {
                std::cout << "✅ Mined block index " << newBlock.getIndex()
                          << " with hash: " << newBlock.getHash() << "\n";
            }

            // Sleep a few seconds so we don't spam the chain
            std::this_thread::sleep_for(std::chrono::seconds(5));
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
    if (!block.getTransactions().empty()) {
	    std::cout << "Transactions: " << block.getTransactions().size() << "\n";
	} else {
	    std::cout << "Transactions: 0\n";
	}
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
    std::transform(senderLower.begin(), senderLower.end(), senderLower.begin(), ::tolower);

    // Check if public key exists, generate if missing
    std::string keyDir = KEY_DIR;
    std::string publicKeyPath = keyDir + senderLower + "_public.pem";

    if (!fs::exists(publicKeyPath)) {
        std::cerr << "⚠️ [WARNING] Public key missing for " << senderLower
                  << "! Generating now...\n";
        Crypto::generateKeysForUser(senderLower);
        // A small wait to ensure key generation completes
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    // Only ONE push_back(tx) — remove the duplicate
    pendingTransactions.push_back(tx);

    // Monitor Dev Fund activity
    if (tx.getSender() == DEV_FUND_ADDRESS || tx.getRecipient() == DEV_FUND_ADDRESS) {
        devFundLastActivity = std::time(nullptr);
        checkDevFundActivity();
    }

    // Save pending transactions to DB
    savePendingTransactionsToDB();

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

// ✅ **Save Blockchain to RocksDB using Protobuf**
bool Blockchain::saveToDB() {
    std::cout << "[DEBUG] Attempting to save blockchain to DB..." << std::endl;

    if (!db) {
        std::cout << "🛑 Skipping full blockchain save: RocksDB not initialized (--nodb mode).\n";
        return true;  // Not an error if we're intentionally in --nodb mode
    }

    alyncoin::BlockchainProto blockchainProto;
    blockchainProto.set_chain_id(1);

    std::set<int> usedIndices;
    int blockCount = 0;
    for (const auto &block : chain) {
        const auto &zk = block.getZkProof();
        if (zk.empty()) {
            std::cerr << "❌ [saveToDB] Cannot save! Block at index " << block.getIndex()
                      << " has empty zkProof. Aborting full save to prevent corruption.\n";
            return false; // 🚨 Abort instead of silently skipping
        }

        int index = block.getIndex();
        if (usedIndices.count(index)) {
            std::cerr << "⚠️ [saveToDB] Duplicate block index detected. Skipping block at index: "
                      << index << ", Hash: " << block.getHash() << "\n";
            continue;
        }

        usedIndices.insert(index);

        std::cout << "[🧪 saveToDB] Block[" << blockCount << "] Index: " << index
                  << ", zkProof: " << zk.size() << " bytes\n";

        alyncoin::BlockProto *blockProto = blockchainProto.add_blocks();
        *blockProto = block.toProtobuf();
        ++blockCount;

        std::cout << "🧱 [DEBUG] Block[" << blockCount << "] hash = " << block.getHash() << std::endl;
    }

    int txCount = 0;
    for (const auto &tx : pendingTransactions) {
        alyncoin::TransactionProto *txProto = blockchainProto.add_pending_transactions();
        *txProto = tx.toProto();
        ++txCount;
    }

    blockchainProto.set_difficulty(difficulty);
    blockchainProto.set_block_reward(blockReward);

    std::string serializedData;
    if (!blockchainProto.SerializeToString(&serializedData)) {
        std::cerr << "❌ [ERROR] Failed to serialize BlockchainProto to string.\n";
        return false;
    }

    std::vector<unsigned char> sampleBytes(serializedData.begin(),
                                           serializedData.begin() + std::min<size_t>(32, serializedData.size()));
    std::cout << "🧪 [DEBUG] First 32 bytes of serialized proto (hex): " << Crypto::toHex(sampleBytes) << std::endl;

    rocksdb::Status status = db->Put(rocksdb::WriteOptions(), "blockchain", serializedData);
    if (!status.ok()) {
        std::cerr << "❌ [ERROR] Failed to save blockchain: " << status.ToString() << "\n";
        return false;
    }

    db->Put(rocksdb::WriteOptions(), "burned_supply", std::to_string(totalBurnedSupply));
    saveVestingInfoToDB();

    std::cout << "✅ Blockchain saved successfully to RocksDB.\n";
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

    std::vector<Block> loadedBlocks;
    std::unordered_set<std::string> seenHashes;

    if (status.ok()) {
        alyncoin::BlockchainProto blockchainProto;
        if (!blockchainProto.ParseFromArray(serializedBlockchain.data(), static_cast<int>(serializedBlockchain.size()))) {
            std::cerr << "❌ [ERROR] Failed to parse blockchain Protobuf data!\n";
            return false;
        }

        for (const auto& blockProto : blockchainProto.blocks()) {
            try {
                Block blk = Block::fromProto(blockProto, true);
                if (seenHashes.insert(blk.getHash()).second)
                    loadedBlocks.push_back(blk);
            } catch (const std::exception& e) {
                std::cerr << "⚠️ [loadFromDB] Skipping corrupt block: " << e.what() << "\n";
            }
        }
        std::cout << "🔁 [loadFromDB] Loaded " << loadedBlocks.size() << " blocks from DB.\n";
    } else {
        std::cerr << "⚠️ RocksDB blockchain not found.\n";
    }

    const auto& pendingFork = getPendingForkChain();
    if (!pendingFork.empty()) {
        std::cout << "🔎 [Fork] Detected pending fork during loadFromDB(). Merging...\n";
        chain = loadedBlocks;
        compareAndMergeChains(pendingFork);
        clearPendingForkChain();
    } else if (!loadedBlocks.empty()) {
        chain = loadedBlocks;
    } else {
        std::string dbPath = DBPaths::getBlockchainDB();
        if (dbPath.find("db_node_b") != std::string::npos || dbPath.find("temp") != std::string::npos) {
            std::cerr << "🧪 [INFO] Peer mode detected — no genesis. Waiting for sync.\n";
            return true;
        }
        std::cerr << "🪐 Creating Genesis Block...\n";
        createGenesisBlock(true);
        std::cout << "⏳ Applying vesting schedule for early supporters...\n";
        applyVestingSchedule();
        db->Put(rocksdb::WriteOptions(), "vesting_initialized", "true");
        std::cout << "✅ Vesting applied & marker set.\n";
    }

    // Explicitly set blockchain difficulty based on last block
    if (!chain.empty()) {
        const Block& latestBlock = chain.back();
        difficulty = latestBlock.getDifficulty();
        std::cout << "⚙️ [loadFromDB] Difficulty explicitly set to latest block difficulty: " << difficulty << "\n";
    } else {
        difficulty = 1; // Default fallback
        std::cout << "⚠️ [loadFromDB] Chain empty after loading. Difficulty reset to default: " << difficulty << "\n";
    }

    // Load burned supply
    std::string burnedSupplyStr;
    if (db->Get(rocksdb::ReadOptions(), "burned_supply", &burnedSupplyStr).ok())
        totalBurnedSupply = std::stod(burnedSupplyStr);
    else
        totalBurnedSupply = 0.0;

    // Check and apply vesting if necessary
    std::string vestingFlag;
    if (db->Get(rocksdb::ReadOptions(), "vesting_initialized", &vestingFlag).ok() && vestingFlag == "true") {
        std::cout << "⏩ Vesting already initialized. Skipping...\n";
    } else {
        std::cout << "⏳ Applying vesting schedule for early supporters...\n";
        applyVestingSchedule();
        db->Put(rocksdb::WriteOptions(), "vesting_initialized", "true");
        std::cout << "✅ Vesting applied & marker set.\n";
    }

    // Always recalculate balances for consistency
    recalculateBalancesFromChain();

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
  for (int i = 1; i <= 10; ++i) {
    std::string supporterAddress = "supporter" + std::to_string(i);
    double initialAmount = 10.0; // Keep same allocation logic
    addVestingForEarlySupporter(supporterAddress, initialAmount);
  }
  saveVestingInfoToDB();
}
// ✅ Serialize Blockchain to Protobuf (safe for cross-node sync)
bool Blockchain::serializeBlockchain(std::string &outData) const {
    alyncoin::BlockchainProto blockchainProto;

    // ✅ Mandatory field to prevent parse failure
    blockchainProto.set_chain_id(1);

    // ✅ Serialize blocks
    int blkCount = 0;
    for (const auto &block : chain) {
        std::cout << "[DEBUG] 🧩 Block[" << blkCount << "] zkProof vector size before toProtobuf: " 
                  << block.getZkProof().size() << " bytes, Hash: " << block.getHash() << "\n";
        alyncoin::BlockProto *protoBlock = blockchainProto.add_blocks();
        *protoBlock = block.toProtobuf();
        blkCount++;
    }

    // ✅ Serialize pending transactions
    for (const auto &tx : pendingTransactions) {
        alyncoin::TransactionProto *txProto = blockchainProto.add_pending_transactions();
        *txProto = tx.toProto();
    }

    blockchainProto.set_difficulty(difficulty);
    blockchainProto.set_block_reward(blockReward);

    // ✅ Serialize to array (needed for ParseFromArray compatibility)
    size_t size = blockchainProto.ByteSizeLong();
    outData.resize(size);
    if (!blockchainProto.SerializeToArray(outData.data(), static_cast<int>(size))) {
        std::cerr << "❌ SerializeToArray failed!\n";
        return false;
    }

    std::cout << "[DEBUG] ✅ BlockchainProto serialization complete. Total Blocks: " << blkCount
              << ", Serialized Size: " << size << " bytes\n";

    return true;
}


// ✅ Deserialize Blockchain from Protobuf
bool Blockchain::deserializeBlockchain(const std::string &data) {
    std::lock_guard<std::mutex> lock(blockchainMutex);

    if (data.empty()) {
        std::cerr << "❌ [ERROR] Received empty Protobuf blockchain data!\n";
        return false;
    }

    std::cout << "📡 [DEBUG] Received Blockchain Data (Size: " << data.size() << " bytes)\n";

    alyncoin::BlockchainProto protoChain;
    if (!protoChain.ParseFromArray(data.data(), static_cast<int>(data.size()))) {
        std::cerr << "❌ [ERROR] Failed to parse decoded blockchain Protobuf using ParseFromArray.\n";
        return false;
    }

    std::cout << "🧪 [DEBUG] Parsed blockchain chain_id = " << protoChain.chain_id() << "\n";

    // Instead of immediately loading, build a temporary receivedChain:
    std::vector<Block> receivedChain;
    for (int i = 0; i < protoChain.blocks_size(); ++i) {
        try {
            Block blk = Block::fromProto(protoChain.blocks(i));
            receivedChain.push_back(blk);
        } catch (const std::exception &e) {
            std::cerr << "❌ [ERROR] Failed to parse BlockProto at index " << i << ": " << e.what() << "\n";
            return false;
        }
    }

    // 🔥 New: Call fork comparison logic
    compareAndMergeChains(receivedChain);

    return true;  // Always return true even if fork was weaker (forkView saved)
}

// ✅ Optional helper for base64 input
bool Blockchain::deserializeBlockchainBase64(const std::string &base64Str) {
    std::string rawData = Crypto::base64Decode(base64Str);
    if (rawData.empty()) {
        std::cerr << "❌ [ERROR] Base64 decode returned empty result.\n";
        return false;
    }

    std::cout << "🧪 [DEBUG] Decoded blockchain data size: " << rawData.size() << " bytes\n";
    std::cout << "🧪 [DEBUG] First 32 bytes (hex): ";
    for (size_t i = 0; i < std::min<size_t>(32, rawData.size()); ++i) {
        printf("%02x", static_cast<unsigned char>(rawData[i]));
    }
    std::cout << std::endl;

    // ✅ Reuse robust logic that compares and merges forks
    return deserializeBlockchain(rawData);
}

//
bool Blockchain::loadFromProto(const alyncoin::BlockchainProto &protoChain) {
    std::cout << "[DEBUG] 🚨 loadFromProto() invoked. Block count: " << protoChain.blocks_size() << "\n";

    if (protoChain.blocks_size() == 0) {
        std::cerr << "⚠️ Skipping loadFromProto: Empty block list received!\n";
        return false;
    }

    chain.clear();
    pendingTransactions.clear();
    difficulty = protoChain.difficulty();
    blockReward = protoChain.block_reward();

    // Load blocks
    for (int i = 0; i < protoChain.blocks_size(); ++i) {
        const auto &blockProto = protoChain.blocks(i);
        std::cout << "[DEBUG] 🧱 Parsing Block[" << i << "]...\n";
        try {
            Block block = Block::fromProto(blockProto);
            chain.push_back(block);
        } catch (const std::exception &e) {
            std::cerr << "❌ [ERROR] Invalid block format during deserialization at index " << i
                      << ": " << e.what() << "\n";
            return false;
        }
    }

    // Load pending transactions
    for (int i = 0; i < protoChain.pending_transactions_size(); ++i) {
        const auto &txProto = protoChain.pending_transactions(i);
        std::cout << "[DEBUG] 🔄 Parsing Pending TX[" << i << "]...\n";
        try {
            Transaction tx = Transaction::fromProto(txProto);
            pendingTransactions.push_back(tx);
        } catch (const std::exception &e) {
            std::cerr << "❌ [ERROR] Invalid transaction format during deserialization at index " << i
                      << ": " << e.what() << "\n";
            return false;
        }
    }

    std::cout << "✅ Blockchain deserialization completed! Blocks: " << chain.size()
              << ", Pending Transactions: " << pendingTransactions.size() << std::endl;

    // 🔁 Ensure full state is recomputed
    recalculateBalancesFromChain();
    validateChainContinuity();

    return true;
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
bool Blockchain::isValidNewBlock(const Block& newBlock) const {
    if (chain.empty()) {
        if (newBlock.getIndex() != 0) {
            std::cerr << "❌ First block must be index 0 (genesis). Block hash: "
                      << newBlock.getHash() << "\n";
            return false;
        }
        return newBlock.isValid("00000000000000000000000000000000", 0); // Genesis: skip PoW
    }

    const Block& lastBlock = getLatestBlock();

    if (newBlock.getIndex() <= lastBlock.getIndex()) {
        std::cerr << "⚠️ [Blockchain] Rejected duplicate/old block. Index: " << newBlock.getIndex()
                  << ", Current: " << lastBlock.getIndex() << "\n";
        return false;
    }

    if (newBlock.getIndex() > lastBlock.getIndex() + 1) {
        int drift = newBlock.getIndex() - (lastBlock.getIndex() + 1);
        if (drift <= 2) {
            std::cout << "⏳ [Blockchain] Slightly future block received. Index: "
                      << newBlock.getIndex() << ", Expected: " << lastBlock.getIndex() + 1 << "\n";
        } else {
            std::cerr << "⚠️ [Blockchain] Received future block. Index: " << newBlock.getIndex()
                      << ", Expected: " << lastBlock.getIndex() + 1 << ". Buffering not implemented.\n";
            return false;
        }
    }

    if (newBlock.getPreviousHash() != lastBlock.getHash()) {
        std::cerr << "❌ Previous hash mismatch for block index "
                  << newBlock.getIndex() << ". Got: " << newBlock.getPreviousHash()
                  << ", Expected: " << lastBlock.getHash() << "\n";
        return false;
    }

    return newBlock.isValid(lastBlock.getHash(), newBlock.getDifficulty());
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

    std::string dilithiumKeyPath = "/root/.alyncoin/keys/" + minerAddress + "_dilithium.key";
    std::string falconKeyPath    = "/root/.alyncoin/keys/" + minerAddress + "_falcon.key";

    if (!Crypto::fileExists(dilithiumKeyPath) || !Crypto::fileExists(falconKeyPath)) {
        std::cerr << "❌ Miner key(s) not found for address: " << minerAddress << "\n";
        return Block();
    }

    std::vector<unsigned char> dilPriv = Crypto::loadDilithiumKeys(minerAddress).privateKey;
    std::vector<unsigned char> falPriv = Crypto::loadFalconKeys(minerAddress).privateKey;

    if (dilPriv.empty() || falPriv.empty()) {
        std::cerr << "❌ Failed to load miner keys for: " << minerAddress << "\n";
        return Block();
    }

    Block newBlock = minePendingTransactions(minerAddress, dilPriv, falPriv);

    if (newBlock.getHash().empty()) {
        std::cerr << "⚠️ Mining returned an empty block. Possibly no valid transactions.\n";
    }

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
const Block& Blockchain::getLatestBlock() const {
    if (chain.empty()) {
        static Block dummyGenesis;
        dummyGenesis.setHash("00000000000000000000000000000000"); // Optional safe fallback
        Logger::warn("[⚠️ WARNING] Blockchain chain is empty. Returning dummy genesis block.");
        return dummyGenesis;
    }
    return chain.back();
}

//
bool Blockchain::hasBlocks() const {
    return !blocks.empty();
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
void Blockchain::loadTransactionsFromDB() {
  if (!db) {
    std::cerr << "❌ RocksDB not initialized. Cannot load transactions!\n";
    return;
  }

  pendingTransactions.clear();

  rocksdb::Iterator* it = db->NewIterator(rocksdb::ReadOptions());
  for (it->SeekToFirst(); it->Valid(); it->Next()) {
    std::string key = it->key().ToString();

    // Only process keys that start with "tx_"
    if (key.rfind("tx_", 0) != 0) continue;

    std::string value = it->value().ToString();
    alyncoin::TransactionProto proto;

    if (!proto.ParseFromString(value)) {
      std::cerr << "⚠️ [CORRUPTED] Invalid transaction proto. Deleting key: " << key << "\n";
      db->Delete(rocksdb::WriteOptions(), key);
      continue;
    }

    Transaction tx = Transaction::fromProto(proto);

    if (tx.getAmount() <= 0) {
      std::cerr << "⚠️ [CORRUPTED] Invalid amount. Deleting: " << key << "\n";
      db->Delete(rocksdb::WriteOptions(), key);
      continue;
    }

    pendingTransactions.push_back(tx);
  }

  delete it;
  std::cout << "✅ Transactions loaded successfully! Pending count: " << pendingTransactions.size() << "\n";
}
//
void Blockchain::loadPendingTransactionsFromDB() {
    if (!db) return;

    pendingTransactions.clear();

    std::unique_ptr<rocksdb::Iterator> it(db->NewIterator(rocksdb::ReadOptions()));
    for (it->SeekToFirst(); it->Valid(); it->Next()) {
        std::string key = it->key().ToString();
        std::string val = it->value().ToString();

        // Use "tx_" prefix to match how we save them:
        if (key.rfind("tx_", 0) == 0) {
            alyncoin::TransactionProto proto;
            if (!proto.ParseFromString(val)) {
                std::cerr << "⚠️ [CORRUPTED] Invalid transaction proto. Deleting key: " << key << "\n";
                db->Delete(rocksdb::WriteOptions(), key);
                continue;
            }
            Transaction tx = Transaction::fromProto(proto);
            if (tx.getAmount() <= 0) {
                db->Delete(rocksdb::WriteOptions(), key);
                continue;
            }
            pendingTransactions.push_back(tx);
        }
    }
    std::cout << "✅ Transactions loaded successfully! Pending count: " << pendingTransactions.size() << "\n";
}

//
void Blockchain::savePendingTransactionsToDB() {
    if (!db) {
        std::cout << "🛑 Skipping pending transaction save: RocksDB not initialized (--nodb mode).\n";
        return;
    }

    std::cout << "[TXDB] 🧹 Cleaning old pending transactions (tx_* keys)...\n";

    // 1) Delete all old "tx_" keys
    {
        rocksdb::Iterator* it = db->NewIterator(rocksdb::ReadOptions());
        int deletedCount = 0;
        for (it->SeekToFirst(); it->Valid(); it->Next()) {
            std::string key = it->key().ToString();
            if (key.rfind("tx_", 0) == 0) {
                db->Delete(rocksdb::WriteOptions(), key);
                ++deletedCount;
            }
        }
        delete it;
        std::cout << "[TXDB] 🗑️ Deleted old tx_ entries: " << deletedCount << "\n";
    }

    // 2) Insert current pendingTransactions
    rocksdb::WriteBatch batch;
    int successCount = 0;
    for (const auto& tx : pendingTransactions) {
        alyncoin::TransactionProto proto = tx.toProto();
        std::string serialized;
        if (!proto.SerializeToString(&serialized)) {
            std::cerr << "❌ [TXDB] Failed to serialize tx with hash " << tx.getHash() << ". Skipping...\n";
            continue;
        }

        std::string key = "tx_" + tx.getHash();  // ✅ USE HASH instead of index
        batch.Put(key, serialized);
        ++successCount;
    }

    // 3) Commit the batch
    rocksdb::Status status = db->Write(rocksdb::WriteOptions(), &batch);
    if (!status.ok()) {
        std::cerr << "❌ [TXDB] Failed to write " << successCount << " pending txs to RocksDB: " << status.ToString() << "\n";
    } else {
        std::cout << "✅ [TXDB] " << successCount << " pending transactions saved to RocksDB.\n";
    }
}

//
void Blockchain::validateChainContinuity() const {
    for (size_t i = 1; i < chain.size(); ++i) {
        const std::string &expected = chain[i - 1].getHash();
        const std::string &received = chain[i].getPreviousHash();

        if (expected != received) {
            std::cerr << "❌ Chain mismatch at index " << i << "!\n";
            std::cerr << "EXPECTED: " << expected << "\n";
            std::cerr << "RECEIVED: " << received << "\n";
        }
    }
}
//
std::vector<Block> Blockchain::getAllBlocks() {
    std::lock_guard<std::mutex> lock(blockchainMutex);
    return chain;  // assuming `chain` is the vector<Block> holding all blocks
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

    // Extract tx hashes
    std::vector<std::string> txHashes;
    for (const auto &tx : newRollupBlock.getTransactions()) {
        txHashes.push_back(tx.getHash());
    }

    // DEBUG: Show rollup proof inputs
    std::cout << "[DEBUG] Verifying RollupBlock:\n";
    std::cout << " ↪️ Proof Length: " << newRollupBlock.getRollupProof().length() << "\n";
    std::cout << " 🌳 Merkle Root: " << newRollupBlock.getMerkleRoot() << "\n";
    std::cout << " 🔐 State Root Before: " << newRollupBlock.getStateRootBefore() << "\n";
    std::cout << " 🔐 State Root After:  " << newRollupBlock.getStateRootAfter() << "\n";
    std::cout << " 📦 TX Count: " << txHashes.size() << "\n";

    if (!ProofVerifier::verifyRollupProof(
            newRollupBlock.getRollupProof(),
            txHashes,
            newRollupBlock.getMerkleRoot(),
            newRollupBlock.getStateRootBefore(),
            newRollupBlock.getStateRootAfter())) {
        std::cerr << "[ERROR] ❌ Rollup block proof verification failed.\n";
        return false;
    }

    std::cout << "✅ Rollup block proof verification passed.\n";
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

  rollupBlock.setDilithiumSignature(rollupSigDilithium);
  rollupBlock.setFalconSignature(rollupSigFalcon);

  return rollupBlock;
}
// Block reward
double Blockchain::calculateBlockReward() {
    const double maxSupply = 100000000.0; // 100 million cap
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

// calculate balance
double Blockchain::calculateBalance(const std::string &address, const std::map<std::string, double> &tempSnapshot) const {
    double baseBalance = getBalance(address);  // This assumes getBalance() already exists and works
    auto it = tempSnapshot.find(address);
    if (it != tempSnapshot.end()) {
        return baseBalance + it->second;
    }
    return baseBalance;
}

// recalculate
void Blockchain::recalculateBalancesFromChain() {
    balances.clear();
    totalSupply = 0.0;
    totalBurnedSupply = 0.0;

    std::unordered_set<std::string> seenBlocks;

    for (size_t i = 0; i < chain.size(); ++i) {
        const Block& block = chain[i];
        const std::string& blockHash = block.getHash();

        if (seenBlocks.count(blockHash)) {
            std::cerr << "⚠️ Duplicate block detected during balance recalculation. Skipping block: " << blockHash << "\n";
            continue;
        }
        seenBlocks.insert(blockHash);

        if (i > 0) {
            const std::string expected = chain[i - 1].getHash();
            const std::string received = block.getPreviousHash();
            if (expected != received) {
                std::cerr << "❌ Previous Hash Mismatch during recalc!\n";
                std::cerr << "EXPECTED: " << expected << "\n";
                std::cerr << "RECEIVED: " << received << "\n";
            }
        }

        const auto& txs = block.getTransactions();
        bool hasSystemTx = false;

        if (!txs.empty()) {
            for (const auto& tx : txs) {
                std::string sender = tx.getSender();
                std::string recipient = tx.getRecipient();
                double amount = tx.getAmount();

                if (sender != "System") {
                    balances[sender] -= amount;
                } else {
                    hasSystemTx = true;
                    totalSupply += amount;
                }

                balances[recipient] += amount;

                if (tx.getMetadata() == "burn") {
                    totalBurnedSupply += amount;
                }
            }
        }

        // ✅ Add block reward manually if it’s not already in a "System" tx
        if (!hasSystemTx && block.getMinerAddress() != "System") {
            double reward = calculateBlockReward();
            balances[block.getMinerAddress()] += reward;
            totalSupply += reward;
        }
    }

    std::cout << "✅ [DEBUG] Balances recalculated from chain. Unique blocks: "
              << seenBlocks.size() << ", Total Supply: " << totalSupply
              << ", Total Burned: " << totalBurnedSupply << "\n";
}

// getCurrentState
std::unordered_map<std::string, double> Blockchain::getCurrentState() const {
    return balances;  // Copy of current L1 state
}
//
void Blockchain::clear(bool force) {
    std::lock_guard<std::mutex> lock(mutex);

    if (!force && !chain.empty()) {
        std::cerr << "⚠️ Blockchain::clear() skipped — chain already initialized. Use force=true to override.\n";
        return;
    }

    std::cout << "🔁 Blockchain::clear() called — resetting state.\n";

    chain.clear();
    pendingTransactions.clear();
    difficulty = DIFFICULTY;
    blockReward = 10.0;
    devFundBalance = 0.0;
    rollupChain.clear();
    balances.clear();
    vestingMap.clear();
    recentTransactionCounts.clear();
    std::cout << "✅ Blockchain cleared (chain + pending txs)\n";
}

// simulateL2StateUpdate
std::unordered_map<std::string, double> Blockchain::simulateL2StateUpdate(
    const std::unordered_map<std::string, double>& currentState,
    const std::vector<Transaction>& l2Txs) const {

    std::unordered_map<std::string, double> updatedState = currentState;

    for (const auto& tx : l2Txs) {
        std::string sender = tx.getSender();
        std::string recipient = tx.getRecipient();
        double amount = tx.getAmount();

        if (updatedState[sender] < amount) {
            std::cerr << "⚠️ L2 State Sim: Insufficient funds for " << sender << "\n";
            continue;
        }

        updatedState[sender] -= amount;
        updatedState[recipient] += amount;
    }

    return updatedState;
}

// getRollupChainSize
int Blockchain::getRollupChainSize() const {
    return rollupChain.size();
}

// getLastRollupHash
std::string Blockchain::getLastRollupHash() const {
    if (rollupChain.empty()) return "GenesisRollup";
    return rollupChain.back().getHash();
}

//getLastRollupProof
std::string Blockchain::getLastRollupProof() const {
    if (rollupChain.empty()) return "GenesisProof";
    return rollupChain.back().getRollupProof();
}

// Append an L2 transaction to pending pool
void Blockchain::addL2Transaction(const Transaction& tx) {
    std::lock_guard<std::mutex> lock(blockchainMutex);
    if (pendingTransactions.size() >= MAX_PENDING_TRANSACTIONS) {
        std::cerr << "[WARN] Max pending transactions reached. Cannot add L2 transaction.\n";
        return;
    }

    // Optional: flag L2 tx for explorer/debugging by setting a metadata field
    Transaction l2tx = tx;
    l2tx.setMetadata("L2"); // assuming you have such a setter, or else just use as-is

    pendingTransactions.push_back(l2tx);
    std::cout << "✅ L2 transaction added. Pending count: " << pendingTransactions.size() << "\n";
}
//
std::string Blockchain::getLatestBlockHash() const {
    return getLatestBlock().getHash();
}

// Filter out and return only L2 transactions
std::vector<Transaction> Blockchain::getPendingL2Transactions() const {
    std::vector<Transaction> l2txs;
    for (const auto& tx : pendingTransactions) {
        if (isL2Transaction(tx)) {
            l2txs.push_back(tx);
        }
    }
    return l2txs;
}

// Determine if a transaction is L2
bool Blockchain::isL2Transaction(const Transaction& tx) const {
    return tx.getMetadata() == "L2";
}

// Get current blockchain height
int Blockchain::getHeight() const {
    return static_cast<int>(chain.size()) - 1;
}

// Get block hash at specific height
std::string Blockchain::getBlockHashAtHeight(int height) const {
    if (height >= 0 && height < static_cast<int>(chain.size())) {
        return chain[height].getHash();
    }
    return "";
}

// Rollback to a specific block height (inclusive)
bool Blockchain::rollbackToHeight(int height) {
    std::lock_guard<std::mutex> lock(blockchainMutex);

    if (height < 0 || height >= static_cast<int>(chain.size())) {
        std::cerr << "❌ Invalid rollback height: " << height << "\n";
        return false;
    }

    chain.resize(height + 1);
    std::cout << "⏪ Chain rolled back to height: " << height << "\n";

    // Recalculate everything post-trim
    recalculateBalancesFromChain();
    saveToDB();

    return true;
}
//
std::string DBPaths::getKeyPath(const std::string &address) {
    return "/root/.alyncoin/keys/" + address + "_combined.key";
}

//
time_t Blockchain::getLastRollupTimestamp() const {
    if (rollupBlocks.empty()) return 0;
    return std::stol(rollupBlocks.back().getTimestamp());
}

//
time_t Blockchain::getFirstPendingL2Timestamp() const {
    for (const auto& tx : pendingTransactions) {
        if (tx.isL2()) return tx.getTimestamp();  // You already tag L2 with "L2:" metadata
    }
    return 0;
}

//
std::vector<Transaction> Blockchain::getAllTransactionsForAddress(const std::string& address) {
    std::vector<Transaction> result;
    for (const Block& blk : this->getAllBlocks()) {
	if (!blk.getTransactions().empty()) {
	    for (const Transaction& tx : blk.getTransactions()) {
	        if (tx.getSender() == address || tx.getRecipient() == address) {
	            result.push_back(tx);
	        }
	    }
	}

    }
    return result;
}

//
int Blockchain::findCommonAncestorIndex(const std::vector<Block>& otherChain) {
    const std::vector<Block>& localChain = getChain();

    int commonIndex = -1;
    int minLength = std::min(localChain.size(), otherChain.size());

    for (int i = 0; i < minLength; ++i) {
        if (localChain[i].getHash() == otherChain[i].getHash()) {
            commonIndex = i;
        } else {
            break;
        }
    }
    return commonIndex;
}
//
bool Blockchain::rollbackToIndex(int index) {
    if (index < 0 || index >= chain.size()) {
        std::cerr << "❌ [Blockchain] Invalid rollback index\n";
        return false;
    }

    chain.resize(index + 1);  // Keep only up to common ancestor
    saveToDB();
    recalculateBalancesFromChain();
    std::cout << "✅ [Blockchain] Rolled back to index: " << index << "\n";
    return true;
}


// ✅ Verify that the incoming chain is logically sound
bool Blockchain::verifyForkSafety(const std::vector<Block>& otherChain) const {
    if (otherChain.empty()) return false;

    if (otherChain.front().getIndex() != 0 ||
        otherChain.front().getPreviousHash() != "00000000000000000000000000000000") {
        std::cerr << "❌ [Fork] Invalid genesis block in incoming chain!\n";
        return false;
    }

    for (size_t i = 1; i < otherChain.size(); ++i) {
        if (otherChain[i].getPreviousHash() != otherChain[i-1].getHash()) {
            std::cerr << "❌ [Fork] Chain continuity error at index " << i << "\n";
            return false;
        }
    }

    return true;
}

// ✅ Find common ancestor index
int Blockchain::findForkCommonAncestor(const std::vector<Block>& otherChain) const {
    int minLength = std::min(chain.size(), otherChain.size());
    int commonIndex = -1;

    for (int i = 0; i < minLength; ++i) {
        if (chain[i].getHash() == otherChain[i].getHash()) {
            commonIndex = i;
        } else {
            break;
        }
    }

    return commonIndex;
}

// ✅ Compute total cumulative difficulty of a chain
uint64_t Blockchain::computeCumulativeDifficulty(const std::vector<Block>& chainRef) const {
    uint64_t total = 0;
    for (const Block& blk : chainRef) {
        if (blk.difficulty >= 0 && blk.difficulty < 64)
            total += (1ULL << blk.difficulty);
        else
            total += 1;
    }
    return total;
}

// ✅ Compare incoming chain and merge if better
void Blockchain::compareAndMergeChains(const std::vector<Block>& otherChain) {
    std::cout << "🔎 [Fork] Comparing chains: local=" << chain.size()
              << " blocks, incoming=" << otherChain.size() << " blocks\n";

    if (otherChain.empty()) {
        std::cerr << "❌ [Fork] Incoming chain is empty.\n";
        return;
    }

    if (!verifyForkSafety(otherChain)) {
        std::cerr << "❌ [Fork] Incoming chain failed safety checks.\n";
        return;
    }

    if (chain.empty()) {
        std::cout << "🆕 [Fork] Local chain is empty. Accepting full chain.\n";
        chain = otherChain;
        saveToDB();
        recalculateBalancesFromChain();
        return;
    }

    if (chain[0].getHash() != otherChain[0].getHash()) {
        std::cerr << "❌ [Fork] Genesis mismatch. Rejecting fork.\n";
        return;
    }

    uint64_t localDiff = computeCumulativeDifficulty(chain);
    uint64_t remoteDiff = computeCumulativeDifficulty(otherChain);

    std::cout << "🔍 [Fork] Local difficulty:   " << localDiff << "\n";
    std::cout << "🔍 [Fork] Incoming difficulty: " << remoteDiff << "\n";

    if (remoteDiff <= localDiff) {
        std::cout << "⚠️ [Fork] Incoming chain is not stronger. Skipping merge.\n";
        return;
    }

    std::cout << "✅ [Fork] Stronger chain received. Attempting merge...\n";

    int commonIndex = findForkCommonAncestor(otherChain);
    if (commonIndex == -1) {
        std::cerr << "⚠️ [Fork] No common ancestor. Replacing full chain.\n";
        chain = otherChain;
        saveToDB();
        recalculateBalancesFromChain();
        return;
    }

    std::cout << "🔗 [Fork] Common ancestor at index: " << commonIndex << "\n";

    if (!rollbackToIndex(commonIndex)) {
        std::cerr << "❌ [Fork] Rollback failed. Merge aborted.\n";
        return;
    }

    for (size_t i = commonIndex + 1; i < otherChain.size(); ++i) {
        if (!addBlock(otherChain[i])) {
            std::cerr << "❌ [Fork] Failed to add block at index " << i << "\n";
            return;
        }
    }

    std::cout << "✅ [Fork] Merge complete. Chain replaced with stronger fork.\n";
}

// ✅ Save forked chain for later inspection
void Blockchain::saveForkView(const std::vector<Block>& forkChain) {
    std::ofstream out("fork_view.json");
    if (!out.is_open()) {
        std::cerr << "❌ [Fork] Failed to open fork_view.json for writing.\n";
        return;
    }

    Json::Value forkJson;
    forkJson["fork_chain"] = Json::arrayValue;
    for (const auto& block : forkChain) {
        forkJson["fork_chain"].append(block.toJSON());
    }

    Json::StreamWriterBuilder writer;
    std::string serialized = Json::writeString(writer, forkJson);
    out << serialized;
    out.close();

    std::cout << "💾 [Fork] Fork chain saved to fork_view.json\n";
}

//
bool Blockchain::deserializeBlockchainForkView(const std::string& rawData, std::vector<Block>& forkOut) const {
    alyncoin::BlockchainProto protoChain;

    if (!protoChain.ParseFromArray(rawData.data(), static_cast<int>(rawData.size()))) {
        std::cerr << "❌ [ERROR] Failed to parse fork Protobuf in deserializeBlockchainForkView.\n";
        return false;
    }

    forkOut.clear();
    int totalBlocks = protoChain.blocks_size();
    std::cout << "📥 [SYNC] Parsing fork chain from peer... Block count: " << totalBlocks << "\n";

    int parsed = 0;
    for (int i = 0; i < totalBlocks; ++i) {
        try {
            const alyncoin::BlockProto& blockProto = protoChain.blocks(i);
            Block blk = Block::fromProto(blockProto, /*allowPartial=*/true); // 🔧 FIXED
            forkOut.push_back(blk);
            std::cout << "✅ Parsed block at index " << blk.getIndex() << " (Hash: " << blk.getHash() << ")\n";
            parsed++;
        } catch (const std::exception& e) {
            std::cerr << "⚠️ [WARN] Skipping block at proto index " << i << ": " << e.what() << "\n";
            continue;
        }
    }

    if (parsed == 0) {
        std::cerr << "❌ [SYNC] No valid blocks could be parsed from fork chain.\n";
        return false;
    }

    std::cout << "🔍 [SYNC] Fork parsing complete. Parsed " << parsed << " / " << totalBlocks << " blocks.\n";
    return true;
}
//
void Blockchain::setPendingForkChain(const std::vector<Block>& fork) {
    pendingForkChain = fork;
}

void Blockchain::clearPendingForkChain() {
    pendingForkChain.clear();
}

const std::vector<Block>& Blockchain::getPendingForkChain() const {
    return pendingForkChain;
}
