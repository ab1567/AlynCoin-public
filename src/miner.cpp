#include <generated/block_protos.pb.h>
#include "miner.h"
#include "blake3.h"
#include "blockchain.h"
#include "config.h"
#include "crypto_utils.h"
#include "mining.h"
#include <atomic>
#include "network.h"
#include <chrono>
#include <fstream>
#include <iostream>
#include <thread>

std::atomic<bool> miningActive{false};

namespace {

const auto kSyncPollInterval = std::chrono::seconds(2);
const auto kInitialCatchupTimeout = std::chrono::seconds(90);
constexpr int kMiningSyncTolerance = 4;

bool chainCaughtUp(Blockchain &blockchain, PeerManager *pm, int tolerance) {
    if (!pm)
        return true;
    const int peerMax = pm->getMaxPeerHeight();
    if (peerMax < 0)
        return true;
    const int localHeight = blockchain.getHeight();
    if (peerMax <= tolerance || localHeight >= peerMax - tolerance)
        return true;
    const uint64_t peerWork = pm->getMaxPeerWork();
    if (peerWork == 0)
        return false;
    return blockchain.getTotalWork() >= peerWork;
}

bool waitForCatchup(Blockchain &blockchain, PeerManager *pm, Network *net,
                    int tolerance, std::chrono::seconds timeout) {
    if (!pm)
        return true;
    bool logged = false;
    auto start = std::chrono::steady_clock::now();
    while (!chainCaughtUp(blockchain, pm, tolerance)) {
        if (!logged) {
            std::cout << "⏳ Waiting for blockchain to catch up before mining...\n";
            logged = true;
        }
        if (net)
            net->autoSyncIfBehind();
        if (timeout.count() > 0 &&
            std::chrono::steady_clock::now() - start > timeout) {
            std::cerr << "⚠️ Proceeding with mining despite lagging behind peers.\n";
            return false;
        }
        std::this_thread::sleep_for(kSyncPollInterval);
    }
    if (logged)
        std::cout << "✅ Local chain caught up with peers. Continuing.\n";
    return true;
}

const char *miningStatusCodeToString(Blockchain::MiningStatusCode code) {
    switch (code) {
    case Blockchain::MiningStatusCode::Success:
        return "SUCCESS";
    case Blockchain::MiningStatusCode::InProgress:
        return "IN_PROGRESS";
    case Blockchain::MiningStatusCode::OfflineMode:
        return "OFFLINE_MODE";
    case Blockchain::MiningStatusCode::Syncing:
        return "SYNCING";
    case Blockchain::MiningStatusCode::RequirePeer:
        return "REQUIRE_PEER";
    case Blockchain::MiningStatusCode::MissingMinerKeys:
        return "MISSING_MINER_KEYS";
    case Blockchain::MiningStatusCode::KeyLoadFailure:
        return "KEY_LOAD_FAILURE";
    case Blockchain::MiningStatusCode::ProofMissing:
        return "PROOF_MISSING";
    case Blockchain::MiningStatusCode::BlockRejected:
        return "BLOCK_REJECTED";
    case Blockchain::MiningStatusCode::EmptyResult:
        return "EMPTY_RESULT";
    case Blockchain::MiningStatusCode::Unknown:
    default:
        return "UNKNOWN";
    }
}

std::string describeMiningStatus(const Blockchain::MiningStatus &status) {
    if (!status.message.empty())
        return status.message;

    switch (status.code) {
    case Blockchain::MiningStatusCode::Success:
        return "Block mined successfully.";
    case Blockchain::MiningStatusCode::InProgress:
        return "Mining job is in progress.";
    case Blockchain::MiningStatusCode::OfflineMode:
        return "Node is in offline mode.";
    case Blockchain::MiningStatusCode::Syncing:
        return "Node is synchronizing with peers.";
    case Blockchain::MiningStatusCode::RequirePeer:
        return "Connect to at least one peer before mining.";
    case Blockchain::MiningStatusCode::MissingMinerKeys:
        return "Miner signing keys are missing.";
    case Blockchain::MiningStatusCode::KeyLoadFailure:
        return "Failed to load miner signing keys.";
    case Blockchain::MiningStatusCode::ProofMissing:
        return "Mined block is missing zk-proof data.";
    case Blockchain::MiningStatusCode::BlockRejected:
        return "Mined block was rejected by consensus.";
    case Blockchain::MiningStatusCode::EmptyResult:
        return "Mining did not produce a valid block.";
    case Blockchain::MiningStatusCode::Unknown:
    default:
        return "Mining failed for an unknown reason.";
    }
}

} // namespace

bool containsValidTransaction(const std::vector<Transaction> &transactions) {
    for (const auto &tx : transactions) {
        if (tx.getSender() != "System") {
            return true;
        }
    }
    return false;
}

void Miner::startMiningProcess(const std::string &minerAddress) {
    try {
        std::cout << "🚀 Starting mining process for: " << minerAddress << std::endl;

        if (miningActive.exchange(true)) {
            std::cerr << "⚠️ Mining already in progress.\n";
            return;
        }

        Blockchain &blockchain = Blockchain::getInstance();

        blockchain.loadPendingTransactionsFromDB();
        blockchain.reloadBlockchainState();  // Load once before loop

        Network *networkPtr = Network::isUninitialized() ? nullptr : &Network::getInstance();
        PeerManager *peerManager = networkPtr ? networkPtr->getPeerManager() : nullptr;

        const auto &cfg = getAppConfig();
        if (cfg.offline_mode) {
            std::cerr << "⚠️ Mining is disabled while offline_mode=true.\n";
            miningActive = false;
            return;
        }
        size_t initialPeers = networkPtr ? networkPtr->getConnectedPeerCount() : 0;
        if (cfg.require_peer_for_mining && initialPeers == 0) {
            std::cerr << "⚠️ Mining requires at least one connected peer.\n";
            miningActive = false;
            return;
        }

        if (auto checkpoint = blockchain.readMiningCheckpoint()) {
            std::cout << "⏮️  Last mining checkpoint height=" << checkpoint->height
                      << " hash=" << checkpoint->hash;
            if (checkpoint->timestamp != 0)
                std::cout << " ts=" << checkpoint->timestamp;
            std::cout << "\n";
        }

        waitForCatchup(blockchain, peerManager, networkPtr, kMiningSyncTolerance,
                       kInitialCatchupTimeout);

        bool warnedBehind = false;

        while (miningActive) {
            if (!Network::isUninitialized()) {
                networkPtr = &Network::getInstance();
                peerManager = networkPtr->getPeerManager();
            } else {
                networkPtr = nullptr;
                peerManager = nullptr;
            }

            const auto &loopCfg = getAppConfig();
            if (loopCfg.offline_mode) {
                std::cerr << "⚠️ Stopping mining loop: offline mode enabled.\n";
                break;
            }
            size_t peersNow = networkPtr ? networkPtr->getConnectedPeerCount() : 0;
            if (loopCfg.require_peer_for_mining && peersNow == 0) {
                std::cerr << "⚠️ Stopping mining loop: no connected peers.\n";
                break;
            }

            if (peerManager && !chainCaughtUp(blockchain, peerManager, kMiningSyncTolerance)) {
                if (!warnedBehind) {
                    std::cerr << "⚠️ Local chain is behind peers; pausing mining for sync.\n";
                    warnedBehind = true;
                }
                if (networkPtr)
                    networkPtr->autoSyncIfBehind();
                std::this_thread::sleep_for(kSyncPollInterval);
                continue;
            }
            warnedBehind = false;

            Block minedBlock = blockchain.mineBlock(minerAddress);
            Blockchain::MiningStatus status = blockchain.getLastMiningStatus();

            if (minedBlock.getHash().empty()) {
                std::cerr << "❌ Mining failed: " << describeMiningStatus(status)
                          << " (" << miningStatusCodeToString(status.code) << ")\n";
                miningActive = false;
                break;
            }

            const auto &zk = minedBlock.getZkProof();
            const auto &dilKey = minedBlock.getPublicKeyDilithium();
            const auto &falKey = minedBlock.getPublicKeyFalcon();

            if (zk.empty() || dilKey.empty() || falKey.empty()) {
                std::cerr << "⚠️ Invalid block content. Missing zkProof or public keys.\n";
                miningActive = false;
                break;
            }

            if (zk.size() > 4096 || dilKey.size() > 4096 || falKey.size() > 4096) {
                std::cerr << "⚠️ Abnormal field size detected. Aborting block.\n";
                miningActive = false;
                break;
            }

            std::string blockMsg = minedBlock.getHash() + minedBlock.getPreviousHash() +
                                   minedBlock.getTransactionsHash() + std::to_string(minedBlock.getTimestamp());

            std::cout << "[SIGN DEBUG] 🔏 Block Message (MINING): " << blockMsg << std::endl;
            std::cout << "[SIGN DEBUG] 🧬 Dilithium PubKey (MINING): " << Crypto::toHex(dilKey) << std::endl;
            std::cout << "[SIGN DEBUG] 🧬 Falcon PubKey (MINING): " << Crypto::toHex(falKey) << std::endl;

            // ✅ Only add and broadcast if block is valid
            if (blockchain.addBlock(minedBlock) ==
                Blockchain::BlockAddResult::Added) {

                if (!Network::isUninitialized()) {
                    Network::getInstance().broadcastBlock(minedBlock);
                    Network::getInstance().broadcastINV({minedBlock.getHash()});
                }

                std::cout << "✅ Block mined, added and broadcasted. Hash: "
                          << minedBlock.getHash() << "\n";
            } else {
                std::cerr << "❌ addBlock() failed — block not added or broadcasted.\n";
            }

            std::this_thread::sleep_for(std::chrono::seconds(1));
        }

    } catch (const std::exception &e) {
        std::cerr << "❌ Fatal error: " << e.what() << std::endl;
    }

    miningActive = false;
}

// ✅ Improved Mining Algorithm: Hybrid PoW (BLAKE3 + Keccak256)
std::string Miner::mineBlock(int difficulty) {
     std::string lastHash = Blockchain::getInstance().getLatestBlock().getHash();
    int nonce = 0;
    std::string newHash;

    while (true) {
        std::ostringstream ss;
        ss << lastHash << nonce;
        std::string candidateHash = Crypto::hybridHash(ss.str());

        // PoW check: leading `difficulty` zeroes
        if (candidateHash.substr(0, difficulty) == std::string(difficulty, '0')) {
            newHash = candidateHash;
            break;
        }
        nonce++;
    }

    std::cout << "✅ Found valid PoW hash: " << newHash << "\n";
    return newHash;
}
