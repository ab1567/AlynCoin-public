#include <generated/block_protos.pb.h>
#include <generated/blockchain_protos.pb.h>
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
#include "db/db_writer.h"
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
#include "rpc/metrics.h"
#include <shared_mutex>
#include <boost/multiprecision/cpp_int.hpp>
#include <unordered_map>
#include <unordered_set>

using boost::multiprecision::cpp_int;

#define EMPTY_TX_ROOT_HASH "0c11a17c8610d35fe17aed2a5a5c682a6cdfb8b6ecf56a95605ebb1475b345de"
#define ROLLUP_CHAIN_FILE "rollup_chain.dat"
namespace fs = std::filesystem;
const std::string BLOCKCHAIN_DB_PATH = DBPaths::getBlockchainDB();
std::vector<StateChannel> stateChannels;
std::vector<RollupBlock> rollupBlocks;
double totalSupply = 0.0;
static Blockchain* g_blockchain_singleton = nullptr;

// --- helper ---------------------------------------------------------------
// Compute BLAKE3 hash of concatenated block hashes for the epoch ending at
// endIndex (inclusive). Returns empty string if insufficient history.
std::string Blockchain::computeEpochRoot(size_t endIndex) const {
    if (endIndex + 1 < static_cast<size_t>(EPOCH_SIZE))
        return "";
    if (endIndex >= chain.size())
        return "";
    size_t start = endIndex + 1 - EPOCH_SIZE;
    std::string combined;
    for (size_t i = start; i <= endIndex; ++i)
        combined += chain[i].getHash();
    return Crypto::blake3(combined);
}
Blockchain& getBlockchain() {
 return Blockchain::getActiveInstance();
}

// Global mutex for blockchain safety. Avoid holding this during RocksDB writes
// to prevent deadlocks across threads.
std::mutex blockchainMutex;
std::atomic<bool> Blockchain::isMining{false};
std::atomic<bool> Blockchain::isRecovering{false};

Blockchain::Blockchain()
    : difficulty(0), miningReward(50.0), db(nullptr), totalBurnedSupply(0.0),
      network(nullptr), totalWork(0) {
  std::cout << "[DEBUG] Default Blockchain constructor called.\n";
}

// ✅ Constructor: Open RocksDB
Blockchain::Blockchain(unsigned short port, const std::string &dbPath, bool bindNetwork, bool isSyncMode)
    : difficulty(0), miningReward(50.0), port(port), dbPath(dbPath), totalWork(0) {

    // Only set network pointer if asked AND it's already initialized, otherwise nullptr
    if (bindNetwork) {
        if (!Network::isUninitialized()) {
            network = Network::getExistingInstance();
            std::cerr << "⚠️ Warning: Network already initialized. Using existing instance.\n";
        } else {
            network = nullptr;
            std::cerr << "⚠️ Network is not initialized; running in limited (local) mode.\n";
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
        std::error_code ec;
        fs::create_directories(dbPathFinal, ec);
        if (ec) {
            std::cerr << "❌ [ERROR] Failed to create RocksDB directory '" << dbPathFinal
                      << "': " << ec.message() << "\n";
        }
    }

    rocksdb::Options options;
    options.create_if_missing = true;
    options.create_missing_column_families = true;

    std::vector<std::string> cfNames;
    rocksdb::Status status = rocksdb::DB::ListColumnFamilies(options, dbPathFinal, &cfNames);
    bool hasCheck = false;
    std::vector<rocksdb::ColumnFamilyDescriptor> cfDesc;
    if (status.ok()) {
        for (const auto& name : cfNames) {
            if (name == "cfCheck") hasCheck = true;
            cfDesc.emplace_back(name, rocksdb::ColumnFamilyOptions());
        }
    }
    if (cfDesc.empty())
        cfDesc.emplace_back(rocksdb::kDefaultColumnFamilyName, rocksdb::ColumnFamilyOptions());
    if (!hasCheck)
        cfDesc.emplace_back("cfCheck", rocksdb::ColumnFamilyOptions());

    std::vector<rocksdb::ColumnFamilyHandle*> handles;
    status = rocksdb::DB::Open(options, dbPathFinal, cfDesc, &handles, &db);
    if (!status.ok()) {
        std::cerr << "❌ [ERROR] Failed to open RocksDB: " << status.ToString() << std::endl;
        exit(1);
    }
    for (size_t i=0;i<cfDesc.size();++i) {
        if (cfDesc[i].name == "cfCheck") cfCheck = handles[i];
    }
    if (!g_dbWriter)
        g_dbWriter = new DBWriter(db);

    std::cout << "[DEBUG] Attempting to load blockchain from DB...\n";
    bool found = loadFromDB();

    if (!found && !isSyncMode) {
        std::cout << "📐 Creating Genesis Block...\n";
        Block genesis = createGenesisBlock();  // Already adds the block
        std::cout << "[DEBUG] ♻️ Genesis zkProof size in chain.front(): "
                  << genesis.getZkProof().size() << " bytes\n";
        saveToDB();  // ✅ Persist genesis block with correct proof
        recalculateBalancesFromChain(); // Only needed if genesis was manually created
        recomputeChainWork();   // <- initialise totalWork = 1 << GENESIS_DIFFICULTY
    } else if (!found) {
        std::cout << "⏳ [INFO] Skipping genesis block — awaiting peer sync...\n";
    }

    loadVestingInfoFromDB();
    loadCheckpointFromDB();

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
    if (cfCheck) {
        db->DestroyColumnFamilyHandle(cfCheck);
        cfCheck = nullptr;
    }
    delete db;
    db = nullptr; // ✅ Prevent potential use-after-free issues
  }
  if (g_dbWriter) {
    delete g_dbWriter;
    g_dbWriter = nullptr;
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
        // Transaction::getTransactionHash() already returns the canonical hash
        const std::string txHash = tx.getTransactionHash();
        // sanity check on data sizes before allocating vectors
        if (tx.getSignatureDilithium().size() > 10000 ||
            tx.getSignatureFalcon().size() > 10000) {
            std::cerr << "[ERROR] Signature too long in tx " << txHash << "\n";
            return false;
        }
        if (tx.getSenderPublicKeyDilithium().size() > 5000 ||
            tx.getSenderPublicKeyFalcon().size() > 5000) {
            std::cerr << "[ERROR] Public key too long in tx " << txHash << "\n";
            return false;
        }
        std::vector<unsigned char> hashBytes = Crypto::fromHex(txHash);

        auto toVec = [](const std::string& data, size_t limit,
                        const std::string& label)
                        -> std::optional<std::vector<unsigned char>> {
            if (data.size() > limit) {
                std::cerr << "[ERROR] " << label << " too long: "
                          << data.size() << " bytes\n";
                return std::nullopt;
            }
            try {
                return std::vector<unsigned char>(data.begin(), data.end());
            } catch (const std::exception& e) {
                std::cerr << "❌ Exception allocating vector for " << label
                          << ": " << e.what() << "\n";
                return std::nullopt;
            }
        };

        auto sigDilithiumOpt =
            toVec(tx.getSignatureDilithium(), 10000, "Dilithium signature");
        auto sigFalconOpt =
            toVec(tx.getSignatureFalcon(), 10000, "Falcon signature");
        auto pubKeyDilithiumOpt =
            toVec(tx.getSenderPublicKeyDilithium(), 5000, "Dilithium pubkey");
        auto pubKeyFalconOpt =
            toVec(tx.getSenderPublicKeyFalcon(), 5000, "Falcon pubkey");

        if (!sigDilithiumOpt || !sigFalconOpt ||
            !pubKeyDilithiumOpt || !pubKeyFalconOpt) {
            return false;
        }

        const std::vector<unsigned char>& sigDilithium = *sigDilithiumOpt;
        const std::vector<unsigned char>& sigFalcon = *sigFalconOpt;
        const std::vector<unsigned char>& pubKeyDilithium = *pubKeyDilithiumOpt;
        const std::vector<unsigned char>& pubKeyFalcon = *pubKeyFalconOpt;

        std::cout << "[DEBUG] Verifying TX: " << txHash << "\n";
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
Block Blockchain::createGenesisBlock(bool force)
{
    if (!force && !chain.empty()) {
        std::cerr << "⚠️  Genesis block already exists. Skipping creation.\n";
        return chain.front();
    }

    /* ----------------------------------------------------------------- */
    std::vector<Transaction> transactions;
    std::string prevHash      = std::string{GENESIS_PARENT_HASH};
    std::string creator       = "System";
    uint64_t    fixedTime     = 1713120000;            // 2024-Apr-14 00:00 UTC
    difficulty  = GENESIS_DIFFICULTY;
    /* ----------------------------------------------------------------- */

    Block genesis(0, prevHash, transactions,
                  creator, difficulty, fixedTime, 0);

    /* hashes / roots --------------------------------------------------- */
    std::string txRoot = genesis.computeTransactionsHash();
    genesis.setTransactionsHash(txRoot);   // mirrors into merkleRoot
    genesis.setMerkleRoot(txRoot);         // invariant keeper
    genesis.setHash( genesis.calculateHash() );

    std::cout << "[DEBUG] Genesis block hash: "
              << genesis.getHash() << '\n';

    /* ------------------------------------------------------------------ */
    /* key generation + signatures                                        */
    std::string rsaKeyPath = getPrivateKeyPath("System");
    if (!Crypto::keysExist("System")) {
        std::cerr << "⚠️  Keys missing for Genesis. Generating...\n";
        Crypto::generateKeysForUser("System");
        Crypto::generatePostQuantumKeys("System");
    }

    std::string rsaSig = Crypto::signMessage(genesis.getHash(),
                                             rsaKeyPath, true);
    if (rsaSig.empty()) {
        std::cerr << "❌ RSA signature failed!\n";
        exit(1);
    }
    genesis.setSignature(rsaSig);

    /* PQ keys ----------------------------------------------------------- */
    auto dilKeys = Crypto::loadDilithiumKeys("System");
    auto falKeys = Crypto::loadFalconKeys("System");
    if (dilKeys.privateKey.empty() || falKeys.privateKey.empty()) {
        std::cerr << "⚠️  PQ keys missing. Regenerating...\n";
        Crypto::generatePostQuantumKeys("System");
        dilKeys = Crypto::loadDilithiumKeys("System");
        falKeys = Crypto::loadFalconKeys("System");
    }

    std::vector<unsigned char> msgBytes = genesis.getSignatureMessage();
    if (msgBytes.size() != 32) {
        std::cerr << "❌ Message hash must be 32 bytes!\n";
        exit(1);
    }
    genesis.setDilithiumSignature(
        Crypto::signWithDilithium(msgBytes, dilKeys.privateKey));
    genesis.setFalconSignature(
        Crypto::signWithFalcon   (msgBytes, falKeys.privateKey));

    if (dilKeys.publicKey.size() != DILITHIUM_PUBLIC_KEY_BYTES ||
        falKeys.publicKey.size() != FALCON_PUBLIC_KEY_BYTES) {
        std::cerr << "❌ PQ public-key length mismatch!\n";
        exit(1);
    }
    genesis.setPublicKeyDilithium(dilKeys.publicKey);
    genesis.setPublicKeyFalcon   (falKeys.publicKey);

    /* zk-STARK proof ---------------------------------------------------- */
    std::string proof = WinterfellStark::generateProof(
            genesis.getHash(), genesis.getPreviousHash(), txRoot);

    if (proof.size() < 64) {
        std::cerr << "❌ zk-STARK proof generation failed!\n";
        exit(1);
    }
    genesis.setZkProof({proof.begin(), proof.end()});
    /* ------------------------------------------------------------------ */

    if (!addBlock(genesis)) {
        std::cerr << "❌ Failed to insert Genesis block!\n";
        exit(1);
    }
    return chain.front();
}

// ✅ Adds block, applies smart burn, and broadcasts to peers
bool Blockchain::addBlock(const Block &block, bool lockHeld) {
    std::unique_lock<std::mutex> lk(chainMtx, std::defer_lock);
    if (!lockHeld)
        lk.lock();
    std::cerr << "[addBlock] Attempting: idx=" << block.getIndex()
              << ", hash=" << block.getHash()
              << ", prev=" << block.getPreviousHash()
              << ", timestamp=" << block.getTimestamp()
              << ", merkleRoot=" << block.getMerkleRoot() << "\n";

    // 1. zkProof required
    if (block.getZkProof().empty()) {
        std::cerr << "❌ [ERROR] Cannot add block with EMPTY zkProof! Block Hash: "
                  << block.getHash() << "\n";
        return false;
    } else {
        std::cout << "[DEBUG] 🧩 addBlock() zkProof length: " << block.getZkProof().size() << " bytes\n";
    }

    // 2. Duplicate hash protection (chain + orphan pool)
    for (const auto &existing : chain)
        if (existing.getHash() == block.getHash()) {
            std::cerr << "⚠️ [addBlock] Duplicate block hash detected (idx=" << block.getIndex()
                      << ", hash=" << block.getHash() << "). Skipping add.\n";
            return true;
        }
    if (orphanHashes.count(block.getHash())) {
        std::cerr << "⚠️ [addBlock] Block already buffered as orphan. Skipping.\n";
        return true;
    }

    // 3. Orphan / fork handling
    if (!chain.empty() && block.getPreviousHash() != chain.back().getHash()) {

        // ⇢ NEW: parent exists → side branch → run fork logic
        if (hasBlockHash(block.getPreviousHash())) {
            std::vector<Block> candidate{block};
            std::string cur = block.getPreviousHash();
            Block p;
            while (getBlockByHash(cur, p)) {
                candidate.insert(candidate.begin(), p);
                cur = p.getPreviousHash();
                if (cur.empty()) break;
            }
            compareAndMergeChains(candidate); // may trigger re-org
            return true; // no orphaning
        }
        std::cerr << "⚠️ [addBlock] Received block before parent. Buffering as orphan.\n";
        if (getOrphanPoolSize() >= MAX_ORPHAN_BLOCKS) {
            std::cerr << "⚠️ [addBlock] Orphan pool limit reached (" << MAX_ORPHAN_BLOCKS
                      << "). Dropping block idx=" << block.getIndex() << "\n";
            return false;
        }
        orphanBlocks[block.getPreviousHash()].push_back(block);
        orphanHashes.insert(block.getHash());

        // === NEW LOGIC: Request missing parent only once ===
        requestMissingParent(block.getPreviousHash());

         return true; // queued as orphan
    }

    // 4. Index checks (genesis or expected)
    if (!chain.empty()) {
        uint64_t expectedIndex = chain.back().getIndex() + 1;
        if (block.getIndex() < expectedIndex) {
            std::cerr << "⚠️ [addBlock] Block index already exists or is stale (Index: " << block.getIndex()
                      << ", Tip: " << chain.back().getIndex() << "). Skipping add.\n";
            return false;
        }
        if (block.getIndex() > expectedIndex) {
            std::cerr << "⚠️ [addBlock] Received future block. Index: " << block.getIndex()
                      << ", Expected: " << expectedIndex << ". Buffering (futureBlocks).\n";
            this->futureBlocks[block.getIndex()] = block;
            return false;
        }
    } else {
        // Only the genesis block is allowed at index 0
        if (!block.isGenesisBlock() && block.getIndex() != 0) {
            std::cerr << "❌ [ERROR] First block must be genesis block (index 0).\n";
            return false;
        }
    }

    // 5. PoW and signature checks
    if (block.isGenesisBlock()) {
        std::cout << "🪐 [GENESIS] Adding genesis block without PoW check.\n";
    } else if (!block.hasValidProofOfWork()) {
        std::cerr << "❌ [addBlock] Invalid PoW! Block hash " << block.getHash()
                  << " does not meet difficulty " << block.getDifficulty() << "\n";
        return false;
    }

    if (!isValidNewBlock(block)) {
        std::cerr << "❌ [addBlock] Invalid block detected. Rejecting!\n";
        return false;
    }

    if (block.getDilithiumSignature().empty() || block.getFalconSignature().empty()) {
        std::cerr << "❌ [addBlock] Block missing signature(s). Rejecting.\n";
        return false;
    }
    if (block.getPublicKeyDilithium().empty() || block.getPublicKeyFalcon().empty()) {
        std::cerr << "❌ [addBlock] Block missing public key(s). Rejecting.\n";
        return false;
    }
    if (block.getPublicKeyFalcon().size() != FALCON_PUBLIC_KEY_BYTES) {
        std::cerr << "❌ [addBlock] Falcon public key length mismatch. Got: "
                  << block.getPublicKeyFalcon().size()
                  << ", Expected: " << FALCON_PUBLIC_KEY_BYTES << "\n";
        return false;
    }
    if (block.getDilithiumSignature().size() < 500 || block.getPublicKeyDilithium().size() < 400) {
        std::cerr << "❌ [addBlock] Dilithium signature or public key too small. Rejecting.\n";
        return false;
    }
    if (block.getFalconSignature().size() < 400) {
        std::cerr << "❌ [addBlock] Falcon signature too small. Rejecting.\n";
        return false;
    }

    // 6. Diagnostics
    std::cerr << "🧪 [addBlock] Safe push diagnostics:\n";
    std::cerr << "  - Index: " << block.getIndex() << "\n";
    std::cerr << "  - Hash: " << block.getHash() << " (" << block.getHash().size() << " bytes)\n";
    std::cerr << "  - zkProof: " << block.getZkProof().size() << "\n";
    std::cerr << "  - Dilithium Sig: " << block.getDilithiumSignature().size() << "\n";
    std::cerr << "  - Falcon Sig: " << block.getFalconSignature().size() << "\n";
    std::cerr << "  - Dilithium PK: " << block.getPublicKeyDilithium().size() << "\n";
    std::cerr << "  - Falcon PK: " << block.getPublicKeyFalcon().size() << "\n";

    // 7. Actually add the block
    Block blkCopy = block;
    cpp_int thisWork = difficultyToWork(block.getDifficulty());
    cpp_int parentWork = chain.empty() ? cpp_int(0) : chain.back().getAccumulatedWork();
    blkCopy.setAccumulatedWork(parentWork + thisWork);

    try {
        std::cerr << "[addBlock] PUSH_BACK to chain: idx=" << blkCopy.getIndex()
                  << ", hash=" << blkCopy.getHash() << std::endl;
        chain.push_back(blkCopy);
        if (block.getDifficulty() >= 0 && block.getDifficulty() < 64)
            totalWork += (1ULL << block.getDifficulty());
        else
            totalWork += 1ULL;
        if (network && network->getPeerManager())
            network->getPeerManager()->setLocalWork(totalWork);
        if (network)
            broadcastNewTip();
    } catch (const std::exception& e) {
        std::cerr << "❌ [CRITICAL][addBlock] push_back failed: " << e.what() << "\n";
        return false;
    } catch (...) {
        std::cerr << "❌ [CRITICAL][addBlock] push_back triggered unknown fatal error.\n";
        return false;
    }

    if (chain.back().getHash() != block.getHash()) {
        std::cerr << "❌ [addBlock] After push_back, block hash mismatch. Possible memory error.\n";
        return false;
    }

    // 8. Remove pending txs included in this block
    if (!block.getTransactions().empty()) {
        std::cerr << "[addBlock] Removing pending txs included in block idx=" << block.getIndex()
                  << ", hash=" << block.getHash() << std::endl;
        for (const auto &tx : block.getTransactions()) {
            pendingTransactions.erase(
                std::remove_if(pendingTransactions.begin(), pendingTransactions.end(),
                               [&tx](const Transaction &pendingTx) {
                                   return pendingTx.getHash() == tx.getHash();
                               }),
                pendingTransactions.end());
        }
    }

    // 9. RocksDB persist
    if (db) {
        alyncoin::BlockProto protoBlock = block.toProtobuf();
        std::string serializedBlock;
        if (!protoBlock.SerializeToString(&serializedBlock)) {
            std::cerr << "❌ [addBlock] Failed to serialize block using Protobuf.\n";
            return false;
        }
        std::string blockKeyByHeight = "block_height_" + std::to_string(block.getIndex());
        rocksdb::Status statusHeight = db->Put(rocksdb::WriteOptions(), blockKeyByHeight, serializedBlock);
        if (!statusHeight.ok()) {
            std::cerr << "❌ [addBlock] Failed to save block by height: " << statusHeight.ToString() << "\n";
            return false;
        }
        std::string blockKeyByHash = "block_" + block.getHash();
        rocksdb::Status statusHash = db->Put(rocksdb::WriteOptions(), blockKeyByHash, serializedBlock);
        if (!statusHash.ok()) {
            std::cerr << "❌ [addBlock] Failed to save block by hash: " << statusHash.ToString() << "\n";
            return false;
        }
        if (!saveToDB()) {
            std::cerr << "❌ [addBlock] Failed to save blockchain to database after adding block.\n";
            return false;
        }
        if (block.getIndex() % 1000 == 0)
            saveCheckpoint(block.getIndex(), block.getHash());
    } else {
        std::cerr << "⚠️ [addBlock] Skipped RocksDB writes: DB not initialized (--nodb mode).\n";
    }

    // 10. Balances/L2 state
    std::cerr << "[addBlock] Recalculating balances and rollup deltas.\n";
    recalculateBalancesFromChain();
    applyRollupDeltasToBalances();
    validateChainContinuity();

    std::cout << "✅ Block added to blockchain. Pending transactions updated and balances recalculated.\n";

    // 11. Try to add any future buffered blocks (old method)
    uint64_t nextIndex = chain.back().getIndex() + 1;
    while (this->futureBlocks.count(nextIndex)) {
        std::cerr << "[addBlock] Applying buffered future block index: " << nextIndex << "\n";
        Block buffered = this->futureBlocks[nextIndex];
        this->futureBlocks.erase(nextIndex);
        addBlock(buffered, true);
        nextIndex++;
    }

    // 12. Try to attach any orphans waiting on this block
    tryAttachOrphans(block.getHash());
    return true;
}

bool Blockchain::tryAddBlock(const Block& block, ValidationResult& out) {
    std::scoped_lock lk(chainMtx);

    if (!chain.empty()) {
        if (block.getIndex() <= chain.back().getIndex())
            return false;
        if (block.getPreviousHash() != chain.back().getHash()) {
            out = ValidationResult::PrevHashMismatch;
            return false;
        }
    }

    bool ok = addBlock(block, true);
    if (!ok) {
        out = ValidationResult::Invalid;
        return false;
    }
    out = ValidationResult::Ok;
    return true;
}

// WARNING: This method is for manual testing or recovery only!
// It is NOT used by network, fork, or mining code.
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

    Block blkCopy = block;
    cpp_int thisWork = difficultyToWork(block.getDifficulty());
    cpp_int parentWork = chain.empty() ? cpp_int(0) : chain.back().getAccumulatedWork();
    blkCopy.setAccumulatedWork(parentWork + thisWork);

    try {
        chain.push_back(blkCopy);
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
        if (block.getIndex() % 1000 == 0)
            saveCheckpoint(block.getIndex(), block.getHash());
    } else {
        std::cerr << "⚠️ [forceAddBlock] RocksDB disabled. Block only added in memory.\n";
    }

    std::cout << "✅ [forceAddBlock] Block forced into chain successfully.\n";
    return true;
}

// ✅ Singleton Instance (network + db)
Blockchain &Blockchain::getInstance(unsigned short port, const std::string &dbPath, bool bindNetwork, bool isSyncMode) {
    static Blockchain instance(port, dbPath, bindNetwork, isSyncMode);
	g_blockchain_singleton = &instance;
    return instance;
}
Blockchain &Blockchain::getInstance() {
    if (!g_blockchain_singleton) throw std::runtime_error("Blockchain singleton not initialized!");
    return *g_blockchain_singleton;
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
rocksdb::DB* Blockchain::getRawDB() {
  return this->db;
}
//
const std::vector<Block> &Blockchain::getChain() const { return chain; }

std::vector<Block> Blockchain::snapshot() const {
    std::lock_guard<std::mutex> lk(chainMtx);
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

  for (const auto &peer : peers) {
    (void)network->requestBlockchainSync(peer);
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
//
bool Blockchain::hasBlock(const std::string &hash) const {
    for (const Block &blk : chain) {
        if (blk.getHash() == hash) {
            return true;
        }
    }
    return false;
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
            ? std::string{GENESIS_PARENT_HASH}
            : newChain.back().getHash();

        if (block.getPreviousHash() != expectedPrevHash) {
            std::cerr << "❌ [ERROR] Invalid previous hash at block index " << block.getIndex()
                      << ". Expected: " << expectedPrevHash << ", Got: " << block.getPreviousHash() << "\n";
            return;
        }

        //if (block.getHash() != block.calculateHash()) {
          //  std::cerr << "❌ [ERROR] Block hash mismatch at index " << block.getIndex() << "\n";
            //return;
        //}

        // ✅ Skip static difficulty validation (LWMA adjusts on mining only)
        newChain.push_back(block);
    }

    if (newChain.size() > chain.size()) {
        std::cout << "✅ Replacing current blockchain with a longer valid chain!\n";
        chain = newChain;
        adjustDifficulty();
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
    if (isRecoveringActive()) {
        std::cout << "[DEBUG] Skipping mining while recovering..." << std::endl;
        return Block();
    }
    if (Network::isUninitialized() || !Network::getInstance().getPeerManager() ||
        Network::getInstance().getPeerManager()->getPeerCount() == 0) {
        std::cerr << "⚠️ Cannot mine without at least one connected peer. If error persists visit alyncoin.com" << std::endl;
        return Block();
    }
    std::cout << "[DEBUG] Waiting on blockchainMutex in minePendingTransactions()...\n";
    std::unique_lock<std::mutex> lock(blockchainMutex);
    std::cout << "[DEBUG] Acquired blockchainMutex in minePendingTransactions()!\n";

    std::map<std::string, double> tempBalances;
    std::vector<Transaction> validTx;
    std::cout << "[DEBUG] Validating and preparing transactions...\n";

    std::time_t timestamp = std::time(nullptr);

    for (const auto &tx : pendingTransactions) {
        if (isL2Transaction(tx)) {
            std::cout << "⚠️ Skipping L2 transaction during L1 mining.\n";
            continue;
        }

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

        validTx.push_back(tx);

        if (devFundAmt > 0.0) {
            Transaction devTx = Transaction::createSystemRewardTransaction(
                DEV_FUND_ADDRESS,
                devFundAmt,
                timestamp,
                ""
            );
            validTx.push_back(devTx);
        }

        std::cout << "🔥 Burned: " << burnAmount
                  << " AlynCoin, 💰 Dev Fund: " << devFundAmt
                  << ", 📤 Final Sent: " << finalAmount << " AlynCoin\n";
    }

    if (validTx.empty()) {
        std::cout << "⛏️ No valid transactions found, creating empty block.\n";
    }

    double blockRewardVal = 0.0;
    if (totalSupply < MAX_SUPPLY) {
        blockRewardVal = calculateBlockReward();
        if (totalSupply + blockRewardVal > MAX_SUPPLY) {
            blockRewardVal = MAX_SUPPLY - totalSupply;
        }
        std::cout << "[DEBUG] totalSupply = " << totalSupply << ", max = " << MAX_SUPPLY << "\n";

        if (blockRewardVal > 0.0) {
            Transaction rewardTx = Transaction::createSystemRewardTransaction(
                minerAddress,
                blockRewardVal,
                timestamp,
                ""
            );
            validTx.push_back(rewardTx);
            totalSupply += blockRewardVal;
            std::cout << "⛏️ Block reward: " << blockRewardVal << " AlynCoin → " << minerAddress << "\n";
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
        timestamp,
        0
    );

    // ✅ Store reward in block
    std::cout << "[DEBUG] Setting reward in block: " << blockRewardVal << "\n";
    newBlock.setReward(blockRewardVal);
    std::cout << "[DEBUG] Block reward now: " << newBlock.getReward() << "\n";

    lock.unlock();
    if (!newBlock.mineBlock(difficulty)) {
        std::cerr << "❌ Mining process returned false!\n";
        return Block();
    }
    lock.lock();

    // If this block completes an epoch, compute aggregated root and dummy proof
    size_t nextIndex = chain.size();
    if ((nextIndex + 1) % EPOCH_SIZE == 0 && chain.size() >= static_cast<size_t>(EPOCH_SIZE - 1)) {
        std::string combined;
        for (size_t i = nextIndex + 1 - EPOCH_SIZE; i < chain.size(); ++i)
            combined += chain[i].getHash();
        combined += newBlock.getHash();
        std::string root = Crypto::blake3(combined);
        newBlock.setEpochRoot(root);
        std::string dummy = WinterfellStark::generateProof(root, root, root);
        newBlock.setEpochProof(std::vector<uint8_t>(dummy.begin(), dummy.end()));
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
    lock.unlock();
    std::cout << "[DEBUG] About to serialize block with reward = " << newBlock.getReward() << "\n";
    saveToDB();

    std::thread([](Block blockCopy) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        if (!Network::isUninitialized()) {
            Network::getInstance().broadcastBlock(blockCopy);
            Blockchain::getInstance().broadcastNewTip();
            if (!blockCopy.getEpochProof().empty()) {
                Network::getInstance().broadcastEpochProof(
                    blockCopy.getIndex() / EPOCH_SIZE,
                    blockCopy.getEpochRoot(),
                    blockCopy.getEpochProof());
            }
        }
    }, newBlock).detach();

    std::cout << "✅ Block mined and added successfully. Total burned supply: " << totalBurnedSupply << "\n";
    return newBlock;
}


// ✅ **Sync Blockchain**
void Blockchain::syncChain(const Json::Value &jsonData) {
    std::unique_lock<std::mutex> lock(blockchainMutex);

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
        lock.unlock();
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

// Begin recovery mode
void Blockchain::startRecovery() {
  isRecovering.store(true);
  std::cout << "[DEBUG] Recovery mode started" << std::endl;
}

// End recovery mode
void Blockchain::finishRecovery() {
  isRecovering.store(false);
  std::cout << "[DEBUG] Recovery mode finished" << std::endl;
}

bool Blockchain::isRecoveringActive() const {
  return isRecovering.load();
}

// ✅ **Reload Blockchain State**
void Blockchain::reloadBlockchainState() {
  loadFromDB();
  loadTransactionsFromDB();
  std::cout << "✅ Blockchain and transactions reloaded!\n";
}

// ✅ **Print Blockchain**
void Blockchain::printBlockchain() const {
    std::unordered_set<std::string> seenHashes;

    std::cout << "=== AlynCoin Blockchain ===\n";
    for (const Block &block : chain) {
        if (seenHashes.find(block.getHash()) != seenHashes.end()) {
            continue;
        }
        seenHashes.insert(block.getHash());

        std::cout << "Block Index: " << block.getIndex() << "\n";
        std::cout << "Hash: " << block.getHash() << "\n";
        std::cout << "Previous Hash: " << block.getPreviousHash() << "\n";
        std::cout << "Miner: " << block.getMinerAddress() << "\n";
        std::cout << "Reward: " << block.getReward() << " AlynCoin\n";
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
void Blockchain::addTransaction(const Transaction &tx) {
    std::lock_guard<std::mutex> lock(blockchainMutex);

    // Lowercase sender name
    std::string senderLower = tx.getSender();
    std::transform(senderLower.begin(), senderLower.end(), senderLower.begin(), ::tolower);

    // If we don\'t have the sender\'s PQ keys cached, reject the transaction
    if (!tx.getSenderPublicKeyDilithium().empty() &&
        !tx.getSenderPublicKeyFalcon().empty()) {
        pendingTransactions.push_back(tx);
    } else {
        std::cerr << "⛔  [addTransaction] No PQ public keys for "
                  << senderLower << ".  Transaction rejected.\n";
        return;
    }

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
        return true;
    }

    /* --- zap stale heights ----------------------------------- */
    rocksdb::WriteBatch batch;
    std::string v;
    int lastHeight = 0;
    if (db->Get(rocksdb::ReadOptions(), "last_height", &v).ok())
        lastHeight = std::stoi(v);
    for (int h = chain.size(); h <= lastHeight; ++h) {
        batch.Delete("block_height_" + std::to_string(h));
    }
    /* ---------------------------------------------------------- */

    alyncoin::BlockchainProto blockchainProto;
    blockchainProto.set_chain_id(1);

    std::set<int> usedIndices;
    int blockCount = 0;
    for (const auto &block : chain) {
        const auto &zk = block.getZkProof();
        if (zk.empty()) {
            std::cerr << "❌ [saveToDB] Cannot save! Block at index " << block.getIndex()
                      << " has empty zkProof. Aborting full save to prevent corruption.\n";
            return false;
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

    for (const auto &tx : pendingTransactions) {
        alyncoin::TransactionProto *txProto = blockchainProto.add_pending_transactions();
        *txProto = tx.toProto();
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

    batch.Put("blockchain", serializedData);
    batch.Put("burned_supply", std::to_string(totalBurnedSupply));

    saveVestingInfoToDB();

    // 🧹 Clear old rollup_* entries
    {
        rocksdb::Iterator* it = db->NewIterator(rocksdb::ReadOptions());
        int deleted = 0;
        for (it->SeekToFirst(); it->Valid(); it->Next()) {
            std::string key = it->key().ToString();
            if (key.rfind("rollup_", 0) == 0) {
                batch.Delete(key);
                ++deleted;
            }
        }
        delete it;
        std::cout << "🧹 Removed " << deleted << " old rollup blocks from DB.\n";
    }

    // ✅ Save rollup blocks with clean re-index
    int rollupCount = 0;
    for (const auto& rb : rollupChain) {
        std::string key = "rollup_" + std::to_string(rollupCount);  // Clean index
        std::string value = rb.serialize();
        batch.Put(key, value);
        ++rollupCount;
    }
    std::cout << "🧱 Saved " << rollupCount << " rollup blocks to DB.\n";

    // ✅ Save final balances
    int balanceCount = 0;
    for (const auto& [address, balance] : balances) {
        batch.Put("balance_" + address, std::to_string(balance));
        ++balanceCount;
    }

    // ✅ Save supply + burned supply (now AFTER rollup deltas applied)
    batch.Put("total_supply", std::to_string(totalSupply));
    batch.Put("burned_supply", std::to_string(totalBurnedSupply));

    std::cout << "💾 Persisted " << balanceCount << " balances to DB.\n";
    batch.Put("last_height", std::to_string(chain.size() - 1));

    rocksdb::WriteOptions wo;
    wo.sync = true;
    rocksdb::Status status;
    if (g_dbWriter)
        status = g_dbWriter->enqueue(std::make_unique<rocksdb::WriteBatch>(batch), wo).get();
    else
        status = db->Write(wo, &batch);
    if (!status.ok()) {
        std::cerr << "❌ [saveToDB] Failed to write batch: " << status.ToString() << "\n";
        return false;
    }
    std::cout << "✅ Blockchain saved successfully to RocksDB.\n";
    return true;
}

// ✅ **Load Blockchain from RocksDB using Protobuf**
bool Blockchain::loadFromDB() {
    static bool skipProofVerification = true;
    std::cout << "[DEBUG] Attempting to load blockchain from DB..." << std::endl;

    if (!db) {
        std::cerr << "❌ RocksDB not initialized!\n";
        return false;
    }

    std::vector<Block> loadedBlocks;
    std::unordered_set<std::string> seenHashes;

    // 🔁 Load blocks one-by-one using "block_height_N" keys
    for (size_t i = 0; ; ++i) {
        std::string key = "block_height_" + std::to_string(i);
        std::string serializedBlock;
        rocksdb::Status status = db->Get(rocksdb::ReadOptions(), key, &serializedBlock);
        if (!status.ok()) break;

        alyncoin::BlockProto proto;
        if (!proto.ParseFromString(serializedBlock)) {
            std::cerr << "⚠️ [loadFromDB] Failed to parse block at height " << i << "\n";
            break;
        }

        try {
            Block blk = Block::fromProto(proto, false);
            if (i && blk.getPreviousHash() != loadedBlocks.back().getHash()) {
                std::cerr << "⚠️  Discontinuity at height " << i << " – truncating DB view here\n";
                break;
            }
            if (seenHashes.insert(blk.getHash()).second)
                loadedBlocks.push_back(blk);
        } catch (const std::exception &e) {
            std::cerr << "⚠️ [loadFromDB] Skipping corrupt block: " << e.what() << "\n";
            break;
        }
    }

    std::cout << "🔁 [loadFromDB] Loaded " << loadedBlocks.size() << " blocks from RocksDB.\n";

    std::vector<Block> pendingFork = getPendingForkChain();
    if (!pendingFork.empty()) {
        std::cout << "🔎 [Fork] Detected pending fork during loadFromDB(). Merging...\n";
        chain = loadedBlocks;
        compareAndMergeChains(pendingFork);
        clearPendingForkChain();
    } else if (!loadedBlocks.empty()) {
        chain = loadedBlocks;
    } else {
        std::cerr << "🪐 Creating Genesis Block...\n";
        createGenesisBlock(true);
        std::cout << "⏳ Applying vesting schedule for early supporters...\n";
        applyVestingSchedule();
        db->Put(rocksdb::WriteOptions(), "vesting_initialized", "true");
        std::cout << "✅ Vesting applied & marker set.\n";
    }

    totalWork = 0;
    for (const auto &b : chain) {
        if (b.getDifficulty() >= 0 && b.getDifficulty() < 64)
            totalWork += (1ULL << b.getDifficulty());
        else
            totalWork += 1ULL;
    }
    if (network && network->getPeerManager())
        network->getPeerManager()->setLocalWork(totalWork);

    difficulty = calculateSmartDifficulty(*this);

    std::string burnedStr;
    if (db->Get(rocksdb::ReadOptions(), "burned_supply", &burnedStr).ok())
        totalBurnedSupply = std::stod(burnedStr);

    recalculateBalancesFromChain();

    std::cout << "🔁 [loadFromDB] Loading rollup blocks from RocksDB...\n";
    int rollupIndex = 0;
    rollupChain.clear();

    while (true) {
        std::string key = "rollup_" + std::to_string(rollupIndex);
        std::string value;
        rocksdb::Status status = db->Get(rocksdb::ReadOptions(), key, &value);
        if (!status.ok()) break;

        try {
            RollupBlock rb = RollupBlock::deserialize(value);
            rollupChain.push_back(rb);
        } catch (...) {
            std::cerr << "⚠️ [loadFromDB] Failed to parse rollup_" << rollupIndex << "\n";
        }

        rollupIndex++;
    }

    applyRollupDeltasToBalances();

    // ───────────────────────────────────────
    // (NEW) Re-derive cumulative work & tell PeerManager
    // ───────────────────────────────────────
    recomputeChainWork();          // updates totalWork

    if (db) {
        for (const auto &[addr, bal] : balances)
            db->Put(rocksdb::WriteOptions(), "balance_" + addr, std::to_string(bal));

        db->Put(rocksdb::WriteOptions(), "total_supply", std::to_string(totalSupply));
        db->Put(rocksdb::WriteOptions(), "burned_supply", std::to_string(totalBurnedSupply));
    }

    std::cout << "💾 Final balance state persisted. Total Supply: " << totalSupply
              << ", Burned: " << totalBurnedSupply
              << ", Addresses: " << balances.size() << "\n";

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
      }
      // ❌ No else/invalid warning, just skip invalid/incomplete JSON
    }
    // ❌ No JSON parsing error warning, just skip
  }
  delete it;
}

void Blockchain::loadCheckpointFromDB()
{
    checkpointHeight = 0;
    if (!db || !cfCheck) return;
    std::unique_ptr<rocksdb::Iterator> it(db->NewIterator(rocksdb::ReadOptions(), cfCheck));
    it->SeekToLast();
    if (it->Valid()) {
        checkpointHeight = std::stoi(it->key().ToString());
    }
}

void Blockchain::saveCheckpoint(int height, const std::string& hash)
{
    if (!db || !cfCheck) return;
    db->Put(rocksdb::WriteOptions(), cfCheck, std::to_string(height), hash);
    checkpointHeight = height;
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
  for (int i = 1; i <= 100; ++i) {
    std::string supporterAddress = "supporter" + std::to_string(i);
    double initialAmount = 100.0; // Keep same allocation logic
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
    std::unique_lock<std::mutex> lock(blockchainMutex);

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
    lock.unlock();
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
        try {
            Block block = Block::fromProto(blockProto);
            cpp_int thisWork = difficultyToWork(block.getDifficulty());
            cpp_int parentWork = chain.empty() ? cpp_int(0) : chain.back().getAccumulatedWork();
            block.setAccumulatedWork(parentWork + thisWork);
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
        try {
            Transaction tx = Transaction::fromProto(txProto);
            pendingTransactions.push_back(tx);
        } catch (const std::exception &e) {
            std::cerr << "❌ [ERROR] Invalid transaction format during deserialization at index " << i
                      << ": " << e.what() << "\n";
            return false;
        }
    }



    // 🔁 Ensure full state is recomputed
    recalculateBalancesFromChain();

    // 🔁 Restore L2 rollup state
    applyRollupDeltasToBalances();

    validateChainContinuity();

    return true;
}


// ✅ **Replace blockchain if a longer valid chain is found**
void Blockchain::replaceChain(const std::vector<Block> &newChain) {
    std::unique_lock<std::mutex> lock(blockchainMutex);

    if (newChain.size() > chain.size()) {
        // 1. Check genesis block matches our chain
        if (chain.size() > 0 && newChain[0].getHash() != chain[0].getHash()) {
            std::cerr << "❌ [replaceChain] Genesis block mismatch. Rejecting chain.\n";
            return;
        }

        // 2. Validate linkage and block validity
        for (size_t i = 1; i < newChain.size(); ++i) {
            if (newChain[i].getPreviousHash() != newChain[i-1].getHash()) {
                std::cerr << "❌ [replaceChain] Invalid block linkage at idx " << i << ". Rejecting chain.\n";
                return;
            }
            if (!newChain[i].isValid(newChain[i-1].getHash(), newChain[i].getDifficulty())) {
                std::cerr << "❌ [replaceChain] Block invalid at idx " << i << ". Rejecting chain.\n";
                return;
            }
        }

        // 3. Replace and update
        chain = newChain;
        recalculateBalancesFromChain();
        lock.unlock();
        saveToDB();
        std::cout << "✅ [replaceChain] Blockchain replaced with a longer, validated chain!\n";
    } else {
        std::cout << "ℹ️ [replaceChain] Not replacing: local chain is longer or equal.\n";
    }
}

// ✅ Replace a prefix of the blockchain using a snapshot
bool Blockchain::replaceChainUpTo(const std::vector<Block>& blocks, int upToHeight) {
    std::unique_lock<std::mutex> lock(blockchainMutex);

    if (blocks.empty() || upToHeight < 0 || static_cast<int>(blocks.size()) != upToHeight + 1) {
        std::cerr << "❌ [replaceChainUpTo] Invalid input parameters\n";
        return false;
    }

    // Validate genesis consistency with existing chain
    if (!chain.empty() && blocks[0].getHash() != chain[0].getHash()) {
        std::cerr << "❌ [replaceChainUpTo] Genesis block mismatch\n";
        return false;
    }

    // Validate linkage and block validity of the snapshot
    for (size_t i = 1; i < blocks.size(); ++i) {
        if (blocks[i].getPreviousHash() != blocks[i-1].getHash()) {
            std::cerr << "❌ [replaceChainUpTo] Invalid block linkage at idx " << i << "\n";
            return false;
        }
        if (!blocks[i].isValid(blocks[i-1].getHash(), blocks[i].getDifficulty())) {
            std::cerr << "❌ [replaceChainUpTo] Block invalid at idx " << i << "\n";
            return false;
        }
    }

    int localHeight = getHeight();
    int reorgDepth = std::max(0, localHeight - upToHeight);
    metrics::reorg_depth.value = reorgDepth;
    if (checkpointHeight > 0 && localHeight - reorgDepth < checkpointHeight - 2) {
        std::cerr << "⚠️ [replaceChainUpTo] Reorg past checkpoint disallowed. depth="
                  << reorgDepth << " checkpoint=" << checkpointHeight << "\n";
        return false;
    }

    auto localPrefix = getChainUpTo(upToHeight);
    auto localWork = computeCumulativeDifficulty(localPrefix);
    auto remoteWork = computeCumulativeDifficulty(blocks);

    if (reorgDepth > 100 ||
        remoteWork * cpp_int(100) <= localWork * cpp_int(101)) {
        std::cerr << "⚠️ [replaceChainUpTo] Rejecting snapshot prefix. reorgDepth="
                  << reorgDepth << " remoteWork=" << remoteWork
                  << " localWork=" << localWork << "\n";
        return false;
    }

    // Truncate and replace local chain with the provided prefix
    chain.assign(blocks.begin(), blocks.end());

    recalculateBalancesFromChain();
    applyRollupDeltasToBalances();
    recomputeChainWork();
    lock.unlock();
    saveToDB();

    std::cout << "✅ [replaceChainUpTo] Replaced chain up to height " << upToHeight << "\n";
    return true;
}
//
bool Blockchain::isValidNewBlock(const Block& newBlock) const {
    if (chain.empty()) {
        if (newBlock.getIndex() != 0) {
            std::cerr << "❌ First block must be index 0 (genesis). Block hash: "
                      << newBlock.getHash() << "\n";
            return false;
        }
        return newBlock.isValid(std::string{GENESIS_PARENT_HASH}, 0);
    }

    const Block& lastBlock = getLatestBlock();

    if (newBlock.getHash() == lastBlock.getHash()) {
        return false; // already have this exact block
    }

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

    if (isRecoveringActive()) {
        std::cerr << "⚠️ Node is recovering. Mining paused." << std::endl;
        return Block();
    }

	std::string dilithiumKeyPath = DBPaths::getKeyDir() + minerAddress + "_dilithium.key";
	std::string falconKeyPath    = DBPaths::getKeyDir() + minerAddress + "_falcon.key";


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

  return sum / static_cast<int>(recentTransactionCounts.size());
}

// ✅ **Update Transaction History for Dynamic Burn Rate**
void Blockchain::updateTransactionHistory(int newTxCount) {
  if (recentTransactionCounts.size() >= 100) {
    recentTransactionCounts.pop_front(); // Keep last 100 blocks' data
  }
  recentTransactionCounts.push_back(newTxCount);
}
// ✅ Get latest block
const Block& Blockchain::getLatestBlock() const {
    if (chain.empty()) {
        static Block dummyGenesis;
        dummyGenesis.setHash(std::string{GENESIS_PARENT_HASH});
        std::cerr <<"[⚠️ WARNING] Blockchain chain is empty. Returning dummy genesis block.\n";
        return dummyGenesis;
    }
    return chain.back();
}
//
bool Blockchain::hasBlocks() const {
    return !chain.empty();
}
//
bool Blockchain::hasBlockHash(const std::string &hash) const {
    for (const auto &blk : chain) {
        if (blk.getHash() == hash)
            return true;
    }
    return false;
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
    cpp_int thisWork = difficultyToWork(block.getDifficulty());
    cpp_int parentWork = chain.empty() ? cpp_int(0) : chain.back().getAccumulatedWork();
    block.setAccumulatedWork(parentWork + thisWork);
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

// Median time past using up to the last 11 blocks.
std::time_t Blockchain::medianTimePast(size_t height) const {
  const size_t window = 11;
  if (chain.empty())
    return std::time(nullptr);  // Fallback if chain is empty

  size_t h = std::min(height, chain.size() - 1);
  size_t count = std::min(window, h + 1);
  std::vector<std::time_t> times;
  times.reserve(count);

  for (size_t i = 0; i < count; ++i) {
    times.push_back(chain[h - i].getTimestamp());
  }
  std::sort(times.begin(), times.end());
  return times[count / 2];
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

        // ✅ Apply and persist L2 deltas
        for (const auto& [address, delta] : newRollupBlock.getCompressedDelta()) {
            balances[address] += delta;

            // ✅ Always persist balance after delta
            if (db) {
                std::string key = "balance_" + address;
                std::string value = std::to_string(balances[address]);
                rocksdb::Status status = db->Put(rocksdb::WriteOptions(), key, value);
                if (!status.ok()) {
                    std::cerr << "⚠️ Failed to persist balance for " << address
                              << ": " << status.ToString() << "\n";
                }
            }
        }

        // ✅ Remove rolled-up txs from pending
        std::unordered_set<std::string> rolledUpTxHashes;
        for (const auto& tx : newRollupBlock.getTransactions()) {
            rolledUpTxHashes.insert(tx.getHash());
        }

        std::vector<Transaction> newPending;
        for (const auto& tx : pendingTransactions) {
            if (!rolledUpTxHashes.count(tx.getHash())) {
                newPending.push_back(tx);
            }
        }
        pendingTransactions = newPending;
        savePendingTransactionsToDB();

        // ✅ Save rollup block itself
        if (db) {
            std::string key = "rollup_" + std::to_string(newRollupBlock.getIndex());
            std::string value = newRollupBlock.serialize();
            db->Put(rocksdb::WriteOptions(), key, value);
            db->Put(rocksdb::WriteOptions(), "burned_supply", std::to_string(totalBurnedSupply));
        }

        std::cout << "[INFO] ✅ Rollup block added successfully. Index: "
                  << newRollupBlock.getIndex() << ". L2 balances updated and persisted.\n";
    } else {
        std::cerr << "[ERROR] ❌ Invalid rollup block. Index: "
                  << newRollupBlock.getIndex() << std::endl;
    }
}

//
bool Blockchain::isRollupBlockValid(const RollupBlock &newRollupBlock, bool skipProofVerification) const {
    // ✅ Validate index continuity
    if (newRollupBlock.getIndex() != rollupChain.size()) {
        std::cerr << "[ERROR] Rollup block index mismatch. Expected: "
                  << rollupChain.size() << ", Got: " << newRollupBlock.getIndex()
                  << std::endl;
        return false;
    }

    // ✅ Validate previous hash
    if (!rollupChain.empty() &&
        newRollupBlock.getPreviousHash() != rollupChain.back().getHash()) {
        std::cerr << "[ERROR] Rollup block previous hash mismatch.\n";
        return false;
    }

    // ✅ Extract tx hashes
    std::vector<std::string> txHashes;
    for (const auto &tx : newRollupBlock.getTransactions()) {
        txHashes.push_back(tx.getHash());
    }

    // ✅ Skip zk-STARK proof verification if flag is set (used during DB load)
    if (skipProofVerification) {
        std::cout << "⚠️ Skipping proof verification during loadFromDB()\n";
        return true;
    }

    // ✅ DEBUG: Show rollup proof inputs
    std::cout << "[DEBUG] Verifying RollupBlock:\n";
    std::cout << " ↪️ Proof Length: " << newRollupBlock.getRollupProof().length() << "\n";
    std::cout << " 🌳 Merkle Root: " << newRollupBlock.getMerkleRoot() << "\n";
    std::cout << " 🔐 State Root Before: " << newRollupBlock.getStateRootBefore() << "\n";
    std::cout << " 🔐 State Root After:  " << newRollupBlock.getStateRootAfter() << "\n";
    std::cout << " 📦 TX Count: " << txHashes.size() << "\n";

    // 🔒 Attempt verification with crash protection
    try {
        if (!ProofVerifier::verifyRollupProof(
                newRollupBlock.getRollupProof(),
                txHashes,
                newRollupBlock.getMerkleRoot(),
                newRollupBlock.getStateRootBefore(),
                newRollupBlock.getStateRootAfter(),
                newRollupBlock.getPreviousHash()))  // ✅ Added missing argument
        {
            std::cerr << "[ERROR] ❌ Rollup block proof verification failed.\n";
            return false;
        }
    } catch (const std::exception &e) {
        std::cerr << "[EXCEPTION] Rollup proof verification threw: " << e.what() << "\n";
        return false;
    } catch (...) {
        std::cerr << "[EXCEPTION] Rollup proof verification crashed unexpectedly.\n";
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
RollupBlock Blockchain::createRollupBlock(const std::vector<Transaction> &offChainTxs) {
    std::unordered_map<std::string, double> stateBefore = balances;
    std::unordered_map<std::string, double> stateAfter = simulateL2StateUpdate(stateBefore, offChainTxs);

    int rollupIndex = rollupChain.size();
    std::string prevHash = rollupIndex == 0 ? "GenesisRollup" : rollupChain.back().getHash();

    RollupBlock rollupBlock(rollupIndex, prevHash, offChainTxs);

    std::string prevProof = rollupIndex == 0 ? "GenesisProof" : rollupChain.back().getRollupProof();

    rollupBlock.generateRollupProof(stateBefore, stateAfter, prevProof);

    return rollupBlock;
}

// Block reward
double Blockchain::calculateBlockReward() {
    const double maxSupply = 100000000.0;

    if (totalSupply >= maxSupply)
        return 0.0;

    blockReward *= 0.9991;       // exponential decay
    if (blockReward < 0.25)
        blockReward = 0.25;      // tail emission

    if (totalSupply + blockReward > maxSupply)
        blockReward = maxSupply - totalSupply;

    return blockReward;
}

// adjustDifficulty
void Blockchain::adjustDifficulty() {
  int newDifficulty = calculateSmartDifficulty(*this);
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

double Blockchain::getAverageDifficulty(int recentCount) const {
    if (chain.empty()) return difficulty;

    int count = std::min(static_cast<int>(chain.size()), recentCount);
    double totalDiff = 0.0;

    for (int i = chain.size() - count; i < chain.size(); ++i)
        totalDiff += chain[i].getDifficulty();

    return (count > 0) ? totalDiff / count : difficulty;
}

int Blockchain::getUniqueMinerCount(int recentCount) const {
    if (chain.empty()) return 1;

    int start = std::max(0, static_cast<int>(chain.size()) - recentCount);
    std::unordered_set<std::string> miners;

    for (int i = start; i < static_cast<int>(chain.size()); ++i) {
        const std::string& addr = chain[i].getMinerAddress();
        if (!addr.empty()) miners.insert(addr);
    }

    return std::max(1, static_cast<int>(miners.size()));
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

        const auto& txs = block.getTransactions();      // L1 only
        const auto& l2txs = block.getL2Transactions();  // Ignored here

        bool hasSystemTx = false;

        for (const auto& tx : txs) {
            const std::string& sender = tx.getSender();
            const std::string& recipient = tx.getRecipient();
            double amount = tx.getAmount();

            if (!sender.empty() && sender != "System") {
                balances[sender] -= amount;
            } else if (sender == "System") {
                hasSystemTx = true;
                totalSupply += amount;
            }

            if (!recipient.empty()) {
                balances[recipient] += amount;
            }

            if (tx.getMetadata() == "burn") {
                totalBurnedSupply += amount;
            }
        }

        if (!l2txs.empty()) {
            std::cout << "⚠️ [DEBUG] Skipping L2 txs in recalc (handled via rollups). Block: " << block.getIndex() << "\n";
        }

        if (!hasSystemTx && !block.getMinerAddress().empty() && block.getMinerAddress() != "System") {
            double reward = calculateBlockReward();
            if (reward > 0.0) {
                balances[block.getMinerAddress()] += reward;
                totalSupply += reward;
            }
        }
    }

    std::cout << "✅ [DEBUG] Balances recalculated from chain. Unique blocks: "
              << seenBlocks.size() << ", Total Supply: " << totalSupply
              << ", Total Burned: " << totalBurnedSupply << "\n";
}

//
void Blockchain::applyRollupDeltasToBalances() {
    std::cout << "🔄 Applying " << rollupChain.size() << " rollup deltas...\n";

    for (const RollupBlock& rollup : rollupChain) {
        for (const Transaction& tx : rollup.getTransactions()) {
            const std::string& sender = tx.getSender();
            const std::string& recipient = tx.getRecipient();
            double amount = tx.getAmount();
            if (sender.empty() || recipient.empty() || amount <= 0.0) continue;

            // Fee calculation
            double burnRate   = std::clamp(static_cast<double>(rollup.getTransactions().size()) / 1000.0, 0.01, 0.05);
            double rawFee     = amount * 0.01;
            double maxFee     = std::min(amount * 0.00005, 1.0);
            double feeAmount  = std::min(rawFee, maxFee);

            double burnAmount = std::min(feeAmount * burnRate, feeAmount);
            double devFundAmt = feeAmount - burnAmount;
            double finalAmount = amount - feeAmount;

            if (sender != "System") {
                balances[sender] -= amount;
            } else {
                totalSupply += amount;
            }

            balances[recipient] += finalAmount;
            balances[DEV_FUND_ADDRESS] += devFundAmt;
            totalBurnedSupply += burnAmount;

            if (tx.getMetadata() == "burn") {
                totalBurnedSupply += amount;
            }

            std::cout << "🔥 Rollup Burned: " << burnAmount
                      << ", 💰 Dev Fund: " << devFundAmt
                      << ", 📤 Final Sent: " << finalAmount << "\n";
        }
    }

    std::cout << "✅ [applyRollupDeltas] L2 rollup balances updated. Total Supply: "
              << totalSupply << ", Burned: " << totalBurnedSupply
              << ", Addresses: " << balances.size() << "\n";
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
    difficulty = calculateSmartDifficulty(*this);
    blockReward = 25.0;
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
    return static_cast<int>(rollupChain.size());
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

    // Collect hashes of transactions already included in rollup blocks
    std::unordered_set<std::string> processedHashes;
    for (const auto& rollupBlock : rollupChain) {
        for (const auto& tx : rollupBlock.getTransactions()) {
            processedHashes.insert(tx.getHash());
        }
    }

    // Only return L2 txs not yet included in any rollup
    for (const auto& tx : pendingTransactions) {
        if (isL2Transaction(tx) && processedHashes.find(tx.getHash()) == processedHashes.end()) {
            l2txs.push_back(tx);
        }
    }

    return l2txs;
}

// Determine if a transaction is L2
bool Blockchain::isL2Transaction(const Transaction& tx) const {
    const std::string& meta = tx.getMetadata();
    return meta == "L2" || (meta.rfind("L2:", 0) == 0);
}
//
void Blockchain::setPendingL2TransactionsIfNotInRollups(const std::vector<Transaction>& allTxs) {
    std::unordered_set<std::string> alreadyRolled;

    for (const auto& rollup : rollupChain) {
        for (const auto& includedTx : rollup.getTransactions()) {
            alreadyRolled.insert(includedTx.getHash());
        }
    }

    // ✅ Reset pendingTransactions to only unrolled L2 txs
    pendingTransactions.clear();

    for (const auto& tx : allTxs) {
        if (isL2Transaction(tx) && !alreadyRolled.count(tx.getHash())) {
            pendingTransactions.push_back(tx);
        }
    }
}
//
std::vector<RollupBlock> Blockchain::getAllRollupBlocks() const {
    return rollupChain;
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
    std::unique_lock<std::mutex> lock(blockchainMutex);

    if (height < 0 || height >= static_cast<int>(chain.size())) {
        std::cerr << "❌ Invalid rollback height: " << height << "\n";
        return false;
    }

    chain.resize(height + 1);
    std::cout << "⏪ Chain rolled back to height: " << height << "\n";

    // Recalculate everything post-trim
    recalculateBalancesFromChain();
    applyRollupDeltasToBalances();
    recomputeChainWork();
    lock.unlock();
    saveToDB();

    return true;
}

//
std::string DBPaths::getKeyPath(const std::string &address) {
    return DBPaths::getKeyDir() + address + "_combined.key";
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
    if (index < 0 || index >= static_cast<int>(chain.size())) {
        std::cerr << "❌ [Blockchain] Invalid rollback index\n";
        return false;
    }

    chain.resize(index + 1);  // Keep only up to common ancestor
    saveToDB();
    recalculateBalancesFromChain();
    applyRollupDeltasToBalances();
    recomputeChainWork();          // ← add this line
    std::cout << "✅ [Blockchain] Rolled back to index: " << index << "\n";
    return true;
}


// ✅ Verify that the incoming chain is logically sound
bool Blockchain::verifyForkSafety(const std::vector<Block>& otherChain) const {
    if (otherChain.empty()) return false;

    if (otherChain.front().getIndex() != 0 ||
        otherChain.front().getPreviousHash() != GENESIS_PARENT_HASH) {
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
cpp_int Blockchain::computeCumulativeDifficulty(const std::vector<Block>& chainRef) const {
    if (chainRef.empty())
        return cpp_int(0);
    return chainRef.back().getAccumulatedWork();
}

// Recompute accumulated work for each block in the current chain and
// refresh the cached totalWork value.
void Blockchain::recomputeChainWork() {
    cpp_int cumWork = 0;
    totalWork = 0;
    for (auto &b : chain) {
        cpp_int thisWork = difficultyToWork(b.getDifficulty());
        cumWork += thisWork;
        b.setAccumulatedWork(cumWork);
        if (b.getDifficulty() >= 0 && b.getDifficulty() < 64)
            totalWork += (1ULL << b.getDifficulty());
        else
            totalWork += 1ULL;
    }
    if (network && network->getPeerManager())
        network->getPeerManager()->setLocalWork(totalWork);
}
//
std::vector<Block> Blockchain::getChainUpTo(size_t height) const
{
   std::lock_guard<std::mutex> lk(mutex);
    if (chain.empty())
        return {};

    if (height >= chain.size())
        height = chain.size() - 1;

    return std::vector<Block>(chain.begin(), chain.begin() + height + 1);
}

std::vector<Block> Blockchain::getChainSlice(size_t startHeight, size_t endHeight) const
{
    std::lock_guard<std::mutex> lk(mutex);
    if (chain.empty())
        return {};

    if (endHeight >= chain.size())
        endHeight = chain.size() - 1;
    if (startHeight > endHeight)
        startHeight = endHeight;

    return std::vector<Block>(chain.begin() + startHeight,
                              chain.begin() + endHeight + 1);
}

//
bool Blockchain::tryAppendBlock(const Block &blk)
{
    std::unique_lock<std::mutex> lk(mutex);

    if (blk.getIndex() != static_cast<int>(chain.size()))
        return false;

    if (!chain.empty() && blk.getPreviousHash() != chain.back().getHash())
        return false;

    Block blkCopy = blk;
    cpp_int thisWork = difficultyToWork(blk.getDifficulty());
    cpp_int parentWork = chain.empty() ? cpp_int(0) : chain.back().getAccumulatedWork();
    blkCopy.setAccumulatedWork(parentWork + thisWork);
    chain.push_back(blkCopy);


    return true;
}
// ✅ Compare incoming chain and merge if better
void Blockchain::compareAndMergeChains(const std::vector<Block>& otherChain) {
    std::cout << "🔎 [Fork] Comparing chains: local=" << chain.size()
              << ", incoming=" << otherChain.size() << " blocks\n";

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
        applyRollupDeltasToBalances();
        recomputeChainWork();
        return;
    }

    if (chain[0].getHash() != otherChain[0].getHash()) {
        std::cerr << "❌ [Fork] Genesis mismatch. Rejecting fork.\n";
        return;
    }

    const cpp_int mainWork = computeCumulativeDifficulty(chain);
    const cpp_int newWork  = computeCumulativeDifficulty(otherChain);

    int commonIdxTmp = findForkCommonAncestor(otherChain);
    int reorgDepth = commonIdxTmp == -1 ? chain.size() : chain.size() - commonIdxTmp - 1;
    metrics::reorg_depth.value = reorgDepth;
    int localHeight = getHeight();
    if (checkpointHeight > 0 && localHeight - reorgDepth < checkpointHeight - 2) {
        std::cerr << "⚠️ [Fork] Reorg past checkpoint disallowed. depth=" << reorgDepth
                  << " checkpoint=" << checkpointHeight << std::endl;
        return;
    }
    if (reorgDepth > 100 || newWork <= mainWork * cpp_int(101) / cpp_int(100)) {
        std::cerr << "⚠️ [Fork] Rejected chain with work " << newWork
                  << " (local=" << mainWork << ", reorgDepth=" << reorgDepth << ")" << std::endl;
        return;
    }

    // ✅ CASE: local is prefix — always append, skip difficulty
    bool isPrefix = true;
    for (size_t i = 0; i < std::min(chain.size(), otherChain.size()); ++i) {
        if (chain[i].getHash() != otherChain[i].getHash()) {
            isPrefix = false;
            break;
        }
    }

    if (isPrefix && otherChain.size() > chain.size()) {
        std::cout << "⏩ [Fork] Local chain is prefix. Appending blocks...\n";
        for (size_t i = chain.size(); i < otherChain.size(); ++i) {
            if (!addBlock(otherChain[i])) {
                std::cerr << "❌ [Fork] Failed to append block idx=" << otherChain[i].getIndex() << "\n";
                return;
            }
        }
        saveToDB();
        applyRollupDeltasToBalances();
        return;
    }

    // ✅ CASE: same length but different tip
    if (otherChain.size() == chain.size() &&
        chain.back().getHash() != otherChain.back().getHash()) {
        if (newWork > mainWork ||
            (newWork == mainWork && otherChain.back().getHash() < chain.back().getHash())) {
            std::cerr << "🔁 [Fork] Same length but higher difficulty. Replacing chain.\n";
            chain = otherChain;
            saveToDB();
            recalculateBalancesFromChain();
            applyRollupDeltasToBalances();
            recomputeChainWork();
        } else {
            std::cout << "⚠️ [Fork] Same length chain not stronger. Keeping current.\n";
        }
        return;
    }

    // ✅ CASE: longer but not prefix — use difficulty
    if (newWork < mainWork ||
        (newWork == mainWork && otherChain.back().getHash() >= chain.back().getHash())) {
        std::cout << "⚠️ [Fork] Incoming chain is not stronger. Skipping merge.\n";
        return;
    }

    std::cout << "✅ [Fork] Stronger chain received. Attempting merge...\n";
    int commonIndex = commonIdxTmp;

    if (commonIndex == -1) {
        std::cerr << "⚠️ [Fork] No common ancestor. Replacing full chain.\n";
        chain = otherChain;
        saveToDB();
        recalculateBalancesFromChain();
        applyRollupDeltasToBalances();
        recomputeChainWork();
        return;
    }

    if (!rollbackToIndex(commonIndex)) {
        std::cerr << "❌ [Fork] Rollback failed. Aborting merge.\n";
        return;
    }

    for (size_t i = commonIndex + 1; i < otherChain.size(); ++i) {
        if (!addBlock(otherChain[i])) {
            std::cerr << "❌ [Fork] Failed to add block idx=" << otherChain[i].getIndex() << "\n";
            return;
        }
    }

    saveToDB();
    applyRollupDeltasToBalances();
    std::cout << "✅ [Fork] Chain replaced via merge.\n";
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
    std::lock_guard<std::mutex> lock(blockchainMutex);
    pendingForkChain = fork;
}

void Blockchain::clearPendingForkChain() {
    std::lock_guard<std::mutex> lock(blockchainMutex);
    pendingForkChain.clear();
}

std::vector<Block> Blockchain::getPendingForkChain() const {
    std::lock_guard<std::mutex> lock(blockchainMutex);
    return pendingForkChain;
}
//
bool Blockchain::openDB(bool readOnly) {
    if (db) return true;
    rocksdb::Options options;
    options.create_if_missing = true;
    rocksdb::Status status;
    if (readOnly)
        status = rocksdb::DB::OpenForReadOnly(options, dbPath, &db);
    else
        status = rocksdb::DB::Open(options, dbPath, &db);
    if (!status.ok()) {
        std::cerr << "❌ [Blockchain] Failed to open RocksDB: " << status.ToString() << std::endl;
        db = nullptr;
        return false;
    }
    return true;
}
//
void Blockchain::purgeDataForResync() {
    if (db) {
        delete db;
        db = nullptr;
    }

    rocksdb::Options opts;
    rocksdb::Status st = rocksdb::DestroyDB(dbPath, opts);
    if (!st.ok()) {
        std::cerr << "[Blockchain] Warning: failed to destroy DB at '" << dbPath
                  << "': " << st.ToString() << std::endl;
    }

    std::filesystem::remove_all(dbPath);
    {
        std::error_code ec;
        std::filesystem::create_directories(dbPath, ec);
        if (ec) {
            std::cerr << "❌ [ERROR] Failed to recreate DB path '" << dbPath
                      << "': " << ec.message() << "\n";
        }
    }

    chain.clear();
    pendingTransactions.clear();
    balances.clear();
    rollupChain.clear();

    if (!openDB(false)) {
        std::cerr << "[Blockchain] Error reopening DB after purge" << std::endl;
    }
}
//
bool Blockchain::getBlockByHash(const std::string& hash, Block& out) const
{
    for (const auto& b : chain)
    {
        if (b.getHash() == hash)
        {
            out = b;
            return true;
        }
    }
    return false;
}

//
// Helper function to request missing parent block from peers (add to Blockchain.cpp)
void Blockchain::requestMissingParent(const std::string& parentHash)
{
    if (requestedParents.count(parentHash)) return;
    requestedParents.insert(parentHash);

    if (!Network::isUninitialized()) {
        alyncoin::net::Frame fr;
        fr.mutable_get_data()->add_hashes(parentHash);
        Network::getInstance().broadcastFrame(fr);
    }

    std::cerr << "📡 requested missing parent " << parentHash << '\n';
}
// Attempt to attach any orphan blocks whose parent hash matches `parentHash`
void Blockchain::tryAttachOrphans(const std::string& parentHash)
{
    auto it = orphanBlocks.find(parentHash);
    if (it == orphanBlocks.end()) return;

    // copy children then erase to avoid iterator invalidation
    auto children = it->second;
    orphanBlocks.erase(it);

    for (const Block& child : children) {
        std::cerr << "[addBlock] Now adding previously orphaned block idx="
                  << child.getIndex() << "\n";
        orphanHashes.erase(child.getHash());
        addBlock(child, true);
    }
}

size_t Blockchain::getOrphanPoolSize() const
{
    size_t total = 0;
    for (const auto& [_, vec] : orphanBlocks)
        total += vec.size();
    return total;
}

void Blockchain::broadcastNewTip()
{
    if (!network)
        return;
    network->broadcastHeight(chain.back().getIndex());
}
