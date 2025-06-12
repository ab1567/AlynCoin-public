#include "blockchain.h"
#include "cli/peer_blacklist_cli.h"
#include "crypto_utils.h"
#include <chrono>
#include "network.h"
#include <thread>
#include "network/peer_blacklist.h"
#include "wallet.h"
#include <fstream>
#include <iostream>
#include <json/json.h>
#include <limits>
#include <string>
#include <filesystem>
#include "db/db_paths.h"
#include "governance/dao.h"
#include "governance/devfund.h"
#include "governance/dao_storage.h"
#include <ctime>
#include "db/db_instance.h"
#include "zk/recursive_proof_helper.h"
#include "difficulty.h"
#include "miner.h"
#include "self_healing/self_healing_node.h"
#include <unordered_set>
#include "httplib.h"
#include "json.hpp"
#include <thread>
#include "nft/nft.h"
#include "nft/nft_storage.h"
#include "nft/crypto/aes_utils.h"
#include <map>
#include <regex>
#include "nft/nft_utils.h"

// --- AlynCoin RPC Server (port 1567) ---
void start_rpc_server(Blockchain* blockchain, Network* network, int rpc_port = 1567) {
    httplib::Server svr;

svr.Post("/rpc", [blockchain, network](const httplib::Request& req, httplib::Response& res) {
    nlohmann::json input;
    try {
        input = nlohmann::json::parse(req.body);
    } catch (...) {
        res.status = 400;
        res.set_content("{\"error\":\"invalid json\"}", "application/json");
        return;
    }

    nlohmann::json output;
    std::string method = input.value("method", "");
    auto params = input.value("params", nlohmann::json::array());

    try {
        // Wallet
        if (method == "balance") {
            std::string addr = params.at(0);
            double bal = blockchain->getBalance(addr);
            output = {{"result", bal}};
        }
	else if (method == "createwallet") {
	    if (params.size() < 1) {
	        output = {{"error", "Missing wallet name parameter"}};
	    } else {
	        std::string name = params.at(0);
	        try {
	            Wallet w(name, DBPaths::getKeyDir());
	            output = {{"result", w.getAddress()}};
	        } catch (const std::exception &e) {
	            output = {{"error", std::string("Wallet creation failed: ") + e.what()}};
	        }
	    }
	}
	else if (method == "loadwallet") {
	    if (params.size() < 1) {
	        output = {{"error", "Missing wallet name parameter"}};
	    } else {
	        std::string name = params.at(0);
	        std::string priv = DBPaths::getKeyDir() + name + "_private.pem";
	        std::string dil = DBPaths::getKeyDir() + name + "_dilithium.key";
	        std::string fal = DBPaths::getKeyDir() + name + "_falcon.key";
	        if (!std::filesystem::exists(priv) ||
	            !std::filesystem::exists(dil) ||
	            !std::filesystem::exists(fal)) {
	            output = {{"error", "Wallet key files not found for: " + name}};
	        } else {
	            try {
	                Wallet w(priv, DBPaths::getKeyDir(), name);
	                // Save as current wallet for convenience
	                std::ofstream(DBPaths::getHomePath() + "/.alyncoin/current_wallet.txt") << w.getAddress();
	                output = {{"result", w.getAddress()}};
	            } catch (const std::exception &e) {
	                output = {{"error", std::string("Wallet load failed: ") + e.what()}};
	            }
	        }
	    }
	}
        // Mine One Block
        else if (method == "mineonce") {
            std::string miner = params.at(0);
            Block mined = blockchain->mineBlock(miner);
            if (!mined.getHash().empty()) {
                blockchain->saveToDB();
                if (network) network->broadcastBlock(mined);
                blockchain->reloadBlockchainState();
                output = {{"result", mined.getHash()}};
            } else {
                output = {{"error", "Mining failed"}};
            }
        }
        // Start Mining Loop (Non-blocking trigger, returns immediately)
        // NOTE: This RPC spawns an infinite mining thread on the server and
        // does not provide a stop mechanism or return mined block hashes.
        // The GUI now prefers calling "mineonce" repeatedly instead.
        else if (method == "mineloop") {
            std::string miner = params.at(0);
            std::thread([blockchain, network, miner]() {
                while (true) {
                    blockchain->loadPendingTransactionsFromDB();
                    Block minedBlock = blockchain->mineBlock(miner);
                    if (!minedBlock.getHash().empty()) {
                        blockchain->saveToDB();
                        try {
                            blockchain->reloadBlockchainState();
                            if (network) network->broadcastBlock(minedBlock);
                        } catch (...) {}
                    }
                    std::this_thread::sleep_for(std::chrono::seconds(2));
                }
            }).detach();
            output = {{"result", "Mining loop started"}};
        }
        // Stats
        else if (method == "stats") {
            nlohmann::json stats = {
                {"blocks", blockchain->getBlockCount()},
                {"difficulty", calculateSmartDifficulty(*blockchain)},
                {"supply", blockchain->getTotalSupply()},
                {"burned", blockchain->getTotalBurnedSupply()},
                {"devfund", blockchain->getBalance("DevFundWallet")}
            };
            output = {{"result", stats}};
        }
	//
        else if (method == "syncstatus") {
            uint64_t localHeight = blockchain->getHeight();
            uint64_t networkHeight = 0;
            bool synced = false;
            if (network && network->getPeerManager()) {
                networkHeight = network->getPeerManager()->getMedianNetworkHeight();
                // Treat networkHeight=0 as "unknown" rather than unsynced
                // so the GUI can start even before any peers report heights.
                synced = (networkHeight == 0 || localHeight >= networkHeight);
            } else {
                synced = true; // assume synced if no network
            }
            nlohmann::json status = {
                {"local_height", localHeight},
                {"network_height", networkHeight},
                {"synced", synced}
            };
            output = {{"result", status}};
        }
        // Send L1 Transaction
        else if (method == "sendl1" || method == "sendl2") {
            std::string from = params.at(0);
            std::string to = params.at(1);
            double amount = params.at(2);
            std::string metadata = params.at(3);
            auto dil = Crypto::loadDilithiumKeys(from);
            auto fal = Crypto::loadFalconKeys(from);
            Transaction tx(from, to, amount, "", metadata, time(nullptr));
            if (method == "sendl2") tx.setMetadata("L2:" + metadata);
            tx.signTransaction(dil.privateKey, fal.privateKey);
            if (!tx.getSignatureDilithium().empty() && !tx.getSignatureFalcon().empty()) {
                blockchain->addTransaction(tx);
                blockchain->savePendingTransactionsToDB();
                if (network) network->broadcastTransaction(tx);
                output = {{"result", "Transaction broadcasted"}};
            } else {
                output = {{"error", "Transaction signing failed"}};
            }
        }
        // Rollup Block
        else if (method == "rollup" || method == "recursive-rollup") {
            std::string walletAddr = params.at(0);
            blockchain->loadPendingTransactionsFromDB();
            std::vector<Transaction> allTxs = blockchain->getPendingTransactions();
            blockchain->setPendingL2TransactionsIfNotInRollups(allTxs);
            std::vector<Transaction> l2Transactions = blockchain->getPendingL2Transactions();
            if (l2Transactions.empty()) {
                output = {{"error", "No pending L2 transactions to roll up"}};
            } else {
                std::unordered_map<std::string, double> stateBefore = blockchain->getCurrentState();
                std::unordered_map<std::string, double> stateAfter =
                    blockchain->simulateL2StateUpdate(stateBefore, l2Transactions);

                RollupBlock rollup(
                    blockchain->getRollupChainSize(),
                    blockchain->getLastRollupHash(),
                    l2Transactions
                );
                std::string prevRecursive = blockchain->getLastRollupProof();
                rollup.generateRollupProof(stateBefore, stateAfter, prevRecursive);

                if (blockchain->isRollupBlockValid(rollup)) {
                    blockchain->addRollupBlock(rollup);
                    if (network) network->broadcastRollupBlock(rollup);
                    output = {{"result", rollup.getHash()}};
                } else {
                    output = {{"error", "Rollup Block creation failed: Proof invalid"}};
                }
            }
        }
        // Transaction History
	else if (method == "history") {
	    std::string addr = params.at(0);
	Blockchain &b = Blockchain::getInstance();
	    b.loadFromDB();
	    b.reloadBlockchainState();
	    std::vector<nlohmann::json> relevant;
	    std::unordered_map<std::string, std::string> txType;
	    std::unordered_set<std::string> seen;
	    auto toLower = [](std::string s) {
	        std::transform(s.begin(), s.end(), s.begin(), ::tolower);
	        return s;
	    };
	    std::string addrLower = toLower(addr);
	    auto blocks = b.getAllBlocks();
	    for (const auto& blk : blocks) {
	        std::string blockMiner = toLower(blk.getMinerAddress());
	        double reward = blk.getReward();
	        for (const auto& tx : blk.getTransactions()) {
	            std::string hash = tx.getHash().empty() ? tx.getTransactionHash() : tx.getHash();
	            if (!seen.count(hash) &&
	                (toLower(tx.getSender()) == addrLower || toLower(tx.getRecipient()) == addrLower)) {
	                relevant.push_back({
	                    {"from", tx.getSender()},
	                    {"to", tx.getRecipient()},
	                    {"amount", tx.getAmount()},
	                    {"metadata", tx.getMetadata()},
	                    {"hash", hash},
	                    {"timestamp", tx.getTimestamp()},
	                    {"type", "L1"}
	                });
	                txType[hash] = "L1";
	                seen.insert(hash);
	            }
	        }
	        if (blockMiner == addrLower && reward > 0.0) {
	            Transaction rewardTx = Transaction::createSystemRewardTransaction(
	                blk.getMinerAddress(), reward, blk.getTimestamp(), "mined_" + blk.getHash());
	            std::string rewardHash = rewardTx.getHash();
	            if (!seen.count(rewardHash)) {
	                relevant.push_back({
	                    {"from", "system"},
	                    {"to", rewardTx.getRecipient()},
	                    {"amount", rewardTx.getAmount()},
	                    {"metadata", rewardTx.getMetadata()},
	                    {"hash", rewardHash},
	                    {"timestamp", rewardTx.getTimestamp()},
	                    {"type", "Mined"}
	                });
	                txType[rewardHash] = "Mined";
	                seen.insert(rewardHash);
	            }
	        }
	    }
	    auto rollups = b.getAllRollupBlocks();
	    for (const auto& roll : rollups) {
	        for (const auto& tx : roll.getTransactions()) {
	            std::string hash = tx.getHash().empty() ? tx.getTransactionHash() : tx.getHash();
	            if (!seen.count(hash) &&
	                (toLower(tx.getSender()) == addrLower || toLower(tx.getRecipient()) == addrLower)) {
	                relevant.push_back({
	                    {"from", tx.getSender()},
	                    {"to", tx.getRecipient()},
	                    {"amount", tx.getAmount()},
	                    {"metadata", tx.getMetadata()},
	                    {"hash", hash},
	                    {"timestamp", tx.getTimestamp()},
	                    {"type", "L2"}
	                });
	                txType[hash] = "L2";
	                seen.insert(hash);
	            }
	        }
	    }
	    // Add mempool or DB-only txs (optional, if used in your chain)
	    auto allTxs = Transaction::loadAllFromDB();
	    for (const auto& tx : allTxs) {
	        std::string hash = tx.getHash().empty() ? tx.getTransactionHash() : tx.getHash();
	        if (!seen.count(hash) &&
	            (toLower(tx.getSender()) == addrLower || toLower(tx.getRecipient()) == addrLower)) {
	            relevant.push_back({
	                {"from", tx.getSender()},
	                {"to", tx.getRecipient()},
	                {"amount", tx.getAmount()},
	                {"metadata", tx.getMetadata()},
	                {"hash", hash},
	                {"timestamp", tx.getTimestamp()},
	                {"type", "L1"}
            });
	            txType[hash] = "L1";
	            seen.insert(hash);
	        }
	    }
	    // Sort by timestamp ascending
	    std::sort(relevant.begin(), relevant.end(), [](const nlohmann::json& a, const nlohmann::json& b) {
	        return a.value("timestamp", 0) < b.value("timestamp", 0);
	    });
	    // Return as JSON array
	    output = {{"result", relevant}};
	}

        // DAO Proposal Submission
        else if (method == "dao-submit") {
            std::string from = params.at(0);
            std::string desc = params.at(1);
            int type = params.at(2);
            double amt = params.at(3);
            std::string target = params.at(4);
            Proposal prop;
            prop.proposal_id = Crypto::sha256(Crypto::generateRandomHex(16));
            prop.proposer_address = from;
            prop.description = desc;
            prop.type = static_cast<ProposalType>(type);
            prop.transfer_amount = amt;
            prop.target_address = target;
            prop.creation_time = std::time(nullptr);
            prop.deadline_time = prop.creation_time + 86400;
            prop.status = ProposalStatus::PENDING;

            if (DAO::createProposal(prop)) {
                output = {{"result", prop.proposal_id}};
            } else {
                output = {{"error", "Failed to submit proposal"}};
            }
        }
        // DAO Voting
        else if (method == "dao-vote") {
            std::string from = params.at(0);
            std::string propID = params.at(1);
            std::string vote = params.at(2);
            bool yes = (vote == "yes" || vote == "y");
            double weight = blockchain->getBalance(from);
            if (DAO::castVote(propID, yes, static_cast<uint64_t>(weight))) {
                output = {{"result", "Vote cast"}};
            } else {
                output = {{"error", "Failed to vote"}};
            }
        }
        // Dev Fund Balance
        else if (method == "devfund") {
            output = {{"result", blockchain->getBalance("DevFundWallet")}};
        }
        // Mined block stats
        else if (method == "mychain") {
            std::string addr = params.at(0);
            int count = 0;
            double reward = 0.0;
            for (const auto &blk : blockchain->getAllBlocks()) {
                if (blk.getMinerAddress() == addr) {
                    count++;
                    reward += blk.getReward();
                }
            }
            output = {{"result", {{"blocks_mined", count}, {"total_rewards", reward}}}};
        }

        // ===================== NFT SPACE =====================
        else if (method == "nft-mint") {
            // params: [creator, metadata, imageHash, identity (optional)]
            std::string creator = params.at(0);
            std::string metadata = params.at(1);
            std::string imageHash = params.at(2);
            std::string identity = params.size() > 3 ? params.at(3) : "";

            std::string privKeyPath = DBPaths::getKeyDir() + creator + "_private.pem";
            if (!std::filesystem::exists(privKeyPath)) {
                output = {{"error", "Missing private key file for wallet: " + privKeyPath}};
            } else {
                int64_t ts = std::time(nullptr);
                std::string id = generateNFTID(creator, imageHash, ts);
                std::string message = id + creator + creator + metadata + imageHash + std::to_string(ts);
                auto msgHash = Crypto::sha256ToBytes(message);
                auto keypair = Crypto::loadFalconKeys(creator);
                std::vector<uint8_t> sig = Crypto::signWithFalcon(msgHash, keypair.privateKey);

                NFT nft{id, creator, creator, metadata, imageHash, ts, sig};
                nft.creator_identity = identity;
                nft.generateZkStarkProof();

                if (!nft.submitMetadataHashTransaction()) {
                    output = {{"error", "Metadata transaction failed"}};
                } else if (!nft.verifySignature() || !NFTStorage::saveNFT(nft, blockchain->getRawDB())) {
                    output = {{"error", "Failed to verify or save NFT"}};
                } else {
                    output = {{"result", id}};
                }
            }
        }
        else if (method == "nft-transfer") {
            // params: [nftID, newOwner, currentUser]
            std::string nftID = params.at(0);
            std::string newOwner = params.at(1);
            std::string current = params.at(2);
            NFT nft;
            if (!NFTStorage::loadNFT(nftID, nft, blockchain->getRawDB())) {
                output = {{"error", "NFT not found"}};
            } else if (nft.owner != current || nft.revoked) {
                output = {{"error", "Not the owner or NFT is revoked"}};
            } else {
                nft.transferHistory.push_back(current);
                nft.owner = newOwner;
                nft.timestamp = std::time(nullptr);
                std::string message = nft.getSignatureMessage();
                auto msgHash = Crypto::sha256ToBytes(message);
                auto keypair = Crypto::loadFalconKeys(current);
                nft.signature = Crypto::signWithFalcon(msgHash, keypair.privateKey);

                if (!nft.verifySignature() || !NFTStorage::saveNFT(nft, blockchain->getRawDB())) {
                    output = {{"error", "Failed to verify or save transfer"}};
                } else {
                    output = {{"result", "NFT transferred"}};
                }
            }
        }
        else if (method == "nft-remint") {
            // params: [id, newMetadata, reason, currentUser]
            std::string id = params.at(0);
            std::string newMetadata = params.at(1);
            std::string reason = params.at(2);
            std::string currentUser = params.at(3);

            if (currentUser.empty()) {
                output = {{"error", "No wallet loaded or passed"}};
            } else {
                NFT nft;
                if (!NFTStorage::loadNFT(id, nft, blockchain->getRawDB())) {
                    output = {{"error", "NFT not found"}};
                } else if (nft.owner != currentUser || nft.revoked) {
                    output = {{"error", "You are not the owner or NFT is revoked"}};
                } else {
                    int newVersion = 1;
                    if (!nft.version.empty()) {
                        try { newVersion = std::stoi(nft.version) + 1; } catch (...) { newVersion = 1; }
                    }
                    int64_t ts = std::time(nullptr);
                    std::string newId = generateNFTID(currentUser, nft.imageHash, ts);
                    std::string message = newId + currentUser + currentUser + newMetadata + nft.imageHash + std::to_string(ts);
                    auto msgHash = Crypto::sha256ToBytes(message);
                    auto keys = Crypto::loadFalconKeys(currentUser);
                    std::vector<uint8_t> sig = Crypto::signWithFalcon(msgHash, keys.privateKey);

                    NFT updated{newId, currentUser, currentUser, newMetadata, nft.imageHash, ts, sig};
                    updated.version = std::to_string(newVersion);
                    updated.creator_identity = nft.creator_identity;
                    updated.expiry_timestamp = nft.expiry_timestamp;
                    updated.previous_versions = nft.previous_versions;
                    updated.previous_versions.push_back(nft.id);

                    updated.generateZkStarkProof();

                    std::string rehash = Crypto::sha256(updated.metadata + updated.imageHash + updated.version);
                    if (!submitMetadataHashTransaction(rehash, currentUser, "falcon", true)) {
                        output = {{"error", "Metadata transaction failed"}};
                    } else if (!updated.verifySignature() || !NFTStorage::saveNFT(updated, blockchain->getRawDB())) {
                        output = {{"error", "Failed to verify or save updated NFT"}};
                    } else {
                        output = {{"result", newId}};
                    }
                }
            }
        }
        else if (method == "nft-export") {
            // params: [id]
            std::string id = params.at(0);
            NFT nft;
            if (!NFTStorage::loadNFT(id, nft, blockchain->getRawDB())) {
                output = {{"error", "NFT not found"}};
            } else {
                nft.exportToFile();
                output = {{"result", "Exported"}};
            }
        }
        else if (method == "nft-encrypt") {
            // params: [id, plaintext, password]
            std::string id = params.at(0);
            std::string plaintext = params.at(1);
            std::string password = params.at(2);
            NFT nft;
            if (!NFTStorage::loadNFT(id, nft, blockchain->getRawDB())) {
                output = {{"error", "NFT not found"}};
            } else {
                nft.encrypted_metadata = AES::encrypt(plaintext, password);
                NFTStorage::saveNFT(nft, blockchain->getRawDB());
                output = {{"result", "Encrypted metadata stored"}};
            }
        }
        else if (method == "nft-decrypt") {
            // params: [id, password]
            std::string id = params.at(0);
            std::string password = params.at(1);
            NFT nft;
            if (!NFTStorage::loadNFT(id, nft, blockchain->getRawDB())) {
                output = {{"error", "NFT not found"}};
            } else if (nft.encrypted_metadata.empty()) {
                output = {{"result", "No encrypted metadata"}};
            } else {
                try {
                    std::string decrypted = AES::decrypt(nft.encrypted_metadata, password);
                    output = {{"result", decrypted}};
                } catch (const std::exception& e) {
                    output = {{"error", std::string("Decryption failed: ") + e.what()}};
                }
            }
        }
        else if (method == "nft-my") {
            // params: [walletAddress]
            std::string current = params.at(0);
            auto all = NFTStorage::loadAllNFTs(blockchain->getRawDB());
            std::vector<nlohmann::json> owned;
            for (const auto& nft : all) {
                if (nft.owner == current) owned.push_back(nlohmann::json::parse(nft.toJSON()));
            }
            output = {{"result", owned}};
        }
        else if (method == "nft-all") {
            // params: []
            auto all = NFTStorage::loadAllNFTs(blockchain->getRawDB());
            std::vector<nlohmann::json> allJson;
            for (const auto& nft : all) {
                allJson.push_back(nlohmann::json::parse(nft.toJSON()));
            }
            output = {{"result", allJson}};
        }
        else if (method == "nft-stats") {
            // params: []
            auto all = NFTStorage::loadAllNFTs(blockchain->getRawDB());
            int total = 0, zk = 0;
            std::map<std::string, int> typeCount;
            for (const auto& nft : all) {
                ++total;
                if (!nft.zkStarkProof.empty()) ++zk;
                if (!nft.nft_type.empty()) typeCount[nft.nft_type]++;
            }
            std::string topType = "N/A";
            int max = 0;
            for (auto& [type, count] : typeCount) {
                if (count > max) { max = count; topType = type; }
            }
            output = {{"result", {{"total", total}, {"zk-stark", zk}, {"most_common_type", topType}}}};
        }
        else if (method == "nft-verifyhash") {
            // params: [fileDataOrPath]
            std::string filepath = params.at(0);
            std::ifstream file(filepath, std::ios::binary);
            if (!file) {
                output = {{"error", "File not found: " + filepath}};
            } else {
                std::ostringstream buffer;
                buffer << file.rdbuf();
                std::string contents = buffer.str();
                std::string fileHash = Crypto::sha256(contents);
                auto all = NFTStorage::loadAllNFTs(blockchain->getRawDB());
                bool found = false;
                for (const auto& nft : all) {
                    if (nft.imageHash == fileHash) {
                        output = {{"result", nlohmann::json::parse(nft.toJSON())}};
                        found = true;
                        break;
                    }
                }
                if (!found) output = {{"error", "No NFT found matching the file hash"}};
            }
        }
        // ================== END NFT SPACE ==================

        // Unknown method fallback
        else {
            output = {{"error", "Unknown method"}};
        }
    } catch (const std::exception& e) {
        output = {{"error", e.what()}};
    }
    res.set_content(output.dump(), "application/json");
});

    printf("🚀 [AlynCoin RPC] Listening on http://0.0.0.0:%d/rpc\n", rpc_port);
    svr.listen("0.0.0.0", rpc_port);
}

void clearInputBuffer() {
    std::cin.clear();
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
}

int main(int argc, char *argv[]) {
    unsigned short port = DEFAULT_PORT;
    bool portSpecified = false;
    std::string dbPath = DBPaths::getBlockchainDB();
    std::string connectIP = "";
    std::string keyDir = DBPaths::getKeyDir();

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--port" && i + 1 < argc) {
            port = static_cast<unsigned short>(std::stoi(argv[++i]));
            portSpecified = true;
            std::cout << "🌐 Using custom port: " << port << std::endl;
        } else if (arg == "--dbpath" && i + 1 < argc) {
            dbPath = argv[++i];
            std::cout << "📁 Using custom DB path: " << dbPath << std::endl;
        } else if ((arg == "--connect" || arg == "--peer") && i + 1 < argc) {
            connectIP = argv[++i];
            std::cout << "🔗 Will connect to peer: " << connectIP << std::endl;
        } else if (arg == "--keypath" && i + 1 < argc) {
            keyDir = argv[++i];
            if (keyDir.back() != '/') keyDir += '/';
        }
    }
    if (!portSpecified) {
        unsigned short newPort = Network::findAvailablePort(port);
        if (newPort != 0 && newPort != port) {
            port = newPort;
            std::cout << "🌐 Auto-selected available port: " << port << std::endl;
        }
    }
    std::string blacklistPath = dbPath + "/blacklist";
    std::filesystem::create_directories(blacklistPath);

        // Initialize blockchain without binding to the network yet. The network
    // instance will be created immediately afterwards and injected via
    // setNetwork(), preventing the misleading startup warning.
    Blockchain &blockchain = Blockchain::getInstance(port, dbPath, /*bindNetwork=*/false);

     std::unique_ptr<PeerBlacklist> peerBlacklistPtr;
     try {
         peerBlacklistPtr = std::make_unique<PeerBlacklist>(blacklistPath, 3);
     } catch (const std::exception& e) {
         std::cerr << "❌ Failed to init PeerBlacklist: " << e.what() << "\n";
         peerBlacklistPtr = nullptr;
     }

    Network* network = nullptr;
    if (peerBlacklistPtr) {
        network = &Network::getInstance(port, &blockchain, peerBlacklistPtr.get());
        blockchain.setNetwork(network);
    } else {
        std::cerr << "⚠️ Network disabled due to PeerBlacklist failure.\n";
    }

     blockchain.loadFromDB();
     blockchain.reloadBlockchainState();

	// ---- Start RPC server in background thread ----
	std::thread rpc_thread(start_rpc_server, &blockchain, network, 1567);
	rpc_thread.detach();

    // ---- Helpers for CLI block ----
    static std::unordered_set<std::string> cliSeenTxHashes;
    auto getBlockchain = []() -> Blockchain& { return Blockchain::getInstance(); };
    Blockchain* chainPtr = &Blockchain::getInstance();
    std::string cmd = (argc >= 2) ? std::string(argv[1]) : "";

    // ================= CLI COMMAND HANDLERS START =================
std::string currentBinPath = argv[0];
       // mineonce <minerAddress>
if (argc >= 3 && std::string(argv[1]) == "mineonce") {
    std::string minerAddress = argv[2];
    Blockchain &b = Blockchain::getInstance();

    if (!b.loadFromDB()) {
        std::cerr << "❌ Could not load blockchain from DB.\n";
        return 1;
    }

    b.loadPendingTransactionsFromDB();
    std::cout << "⛏️ Mining single block for: " << minerAddress << "\n";
    Block minedBlock = b.mineBlock(minerAddress);

    if (!minedBlock.getHash().empty()) {
        b.saveToDB();
        b.reloadBlockchainState();
        if (!Network::isUninitialized()) {
            Network::getInstance().broadcastBlock(minedBlock);  // ✅ reuse existing Network instance
        }
        std::cout << "✅ Block mined by: " << minerAddress << "\n"
                  << "🧱 Block Hash: " << minedBlock.getHash() << "\n"
                  << "✅ Block added to chain.\n";
    } else {
        std::cerr << "⚠️ Mining failed.\n";
    }

    return 0;
}
// mineloop <minerAddress>
if (argc >= 3 && std::string(argv[1]) == "mineloop") {
    std::string minerAddress = argv[2];
    Blockchain &b = Blockchain::getInstance();

    if (!b.loadFromDB()) {
        std::cerr << "❌ Could not load blockchain from DB.\n";
        return 1;
    }

    std::cout << "🔁 Starting mining loop for: " << minerAddress << "\n";
    while (true) {
        b.loadPendingTransactionsFromDB();
        Block minedBlock = b.mineBlock(minerAddress);

        if (!minedBlock.getHash().empty()) {
            b.saveToDB();

            try {
                b.reloadBlockchainState();
                if (!Network::isUninitialized()) {
                    Network::getInstance().broadcastBlock(minedBlock);  // ✅ no conflict
                }
            } catch (const std::exception &e) {
                std::cerr << "⚠️ reloadBlockchainState() skipped due to network error: " << e.what() << "\n";
            }

            std::cout << "✅ Block mined by: " << minerAddress << "\n"
                      << "🧱 Block Hash: " << minedBlock.getHash() << "\n";
        } else {
            std::cerr << "⚠️ Mining failed or no valid transactions.\n";
        }

        std::this_thread::sleep_for(std::chrono::seconds(2));
    }

    return 0;
}
    // === DAO view ===
    if (cmd == "dao-view" && argc == 2) {
        auto proposals = DAOStorage::getAllProposals();
        std::cout << "\n=== DAO Proposals ===\n";
        for (const auto &p : proposals) {
            std::cout << "📜 ID: " << p.proposal_id << "\n";
            std::cout << "📝 Description: " << p.description << "\n";
            std::cout << "🛍 Type: " << static_cast<int>(p.type) << "\n";
            std::cout << "📅 Deadline: " << p.deadline_time << "\n";
            std::cout << "✅ YES: " << static_cast<uint64_t>(p.yes_votes) << " | ❌ NO: " << static_cast<uint64_t>(p.no_votes) << "\n";
            std::cout << "📌 Status: " << static_cast<int>(p.status) << "\n\n";
        }
        return 0;
    }
    // === Blockchain stats ===
    if (cmd == "stats" && argc >= 2) {
	Blockchain &b = Blockchain::getInstance();
        std::cout << "\n=== Blockchain Stats ===\n";
        std::cout << "Total Blocks: " << b.getBlockCount() << "\n";
        std::cout << "Difficulty: " << calculateSmartDifficulty(b) << "\n";
        std::cout << "Total Supply: " << b.getTotalSupply() << " AlynCoin\n";
        std::cout << "Total Burned Supply: " << b.getTotalBurnedSupply() << " AlynCoin\n";
        std::cout << "Dev Fund Balance: " << b.getBalance("DevFundWallet") << " AlynCoin\n";
        return 0;
    }
    // Wallet create/load
    if (cmd == "createwallet" && argc == 3) {
        try {
            Wallet w(argv[2], keyDir);
            std::cout << "✅ Wallet created: " << w.getAddress() << "\n";
        } catch (const std::exception &e) {
            std::cerr << "❌ Wallet creation failed: " << e.what() << "\n";
            return 1;
        }
        return 0;
    }
    if (cmd == "loadwallet" && argc == 3) {
        std::string name = argv[2];
        std::string priv = keyDir + name + "_private.pem";
        std::string dil = keyDir + name + "_dilithium.key";
        std::string fal = keyDir + name + "_falcon.key";
        if (!std::filesystem::exists(priv) || !std::filesystem::exists(dil) || !std::filesystem::exists(fal)) {
            std::cerr << "❌ Wallet key files not found for: " << name << std::endl;
            return 1;
        }
        try {
            Wallet w(priv, keyDir, name);
            std::ofstream(DBPaths::getHomePath() + "/.alyncoin/current_wallet.txt") << w.getAddress();
            std::cout << "✅ Wallet loaded: " << w.getAddress() << std::endl;
        } catch (const std::exception &e) {
            std::cerr << "❌ Wallet load failed: " << e.what() << std::endl;
            return 1;
        }
        return 0;
    }
// === Balance check (normal or forced) ===
    if ((cmd == "balance" || cmd == "balance-force") && argc >= 3) {
        std::string addr = argv[2];
        // Use the no-network singleton to avoid DB locks
        Blockchain &bb = Blockchain::getInstance();
        if (cmd == "balance-force") bb.reloadBlockchainState();
        std::cout << "Balance: " << bb.getBalance(addr) << " AlynCoin" << std::endl;
        return 0;
    }
// === sendl1 / sendl2 with duplicate filter ===
if ((argc >= 6) && (std::string(argv[1]) == "sendl1" || std::string(argv[1]) == "sendl2")) {
    std::string from = argv[2];
    std::string to = argv[3];
    std::string rawAmount = argv[4];
    std::string metadata = argv[5];

    double amount = -1;
    try {
        amount = std::stod(rawAmount);
    } catch (...) {
        std::cerr << "❌ Invalid amount format: " << rawAmount << "\n";
        return 1;
    }

    // ✅ Allow zero amount only for metadataSink transactions
    if (amount <= 0.0 && to != "metadataSink") {
        std::cerr << "❌ Invalid amount. Zero allowed only when sending to metadataSink.\n";
        return 1;
    }

    Blockchain &b = Blockchain::getInstance();

    // ✅ Skip balance check if it's metadata-only (to metadataSink with 0.0)
    if (!(amount == 0.0 && to == "metadataSink")) {
        double currentBalance = b.getBalance(from);
        if (amount > currentBalance) {
            std::cerr << "❌ Insufficient balance. You have " << currentBalance
                      << " AlynCoin, but tried to send " << amount << ".\n";
            return 1;
        }
    }

    auto dil = Crypto::loadDilithiumKeys(from);
    auto fal = Crypto::loadFalconKeys(from);

    Transaction tx(from, to, amount, "", metadata, time(nullptr));
    if (std::string(argv[1]) == "sendl2") {
        tx.setMetadata("L2:" + metadata);
    }

    // Hash-based deduplication for CLI too (mirrors network, prevents resending on retry)
    std::string txHash = tx.getHash();
    if (cliSeenTxHashes.count(txHash)) {
        std::cerr << "⚠️ Transaction already submitted by this CLI session (hash dedupe).\n";
        return 1;
    }

    for (const auto& existing : b.getPendingTransactions()) {
        if (existing.getSender() == tx.getSender() &&
            existing.getRecipient() == tx.getRecipient() &&
            existing.getAmount() == tx.getAmount() &&
            existing.getMetadata() == tx.getMetadata()) {
            std::cerr << "⚠️ Duplicate transaction already exists in mempool.\n";
            return 1;
        }
    }
    cliSeenTxHashes.insert(txHash);

    tx.signTransaction(dil.privateKey, fal.privateKey);
    if (!tx.getSignatureDilithium().empty() && !tx.getSignatureFalcon().empty()) {
        b.addTransaction(tx);
        b.savePendingTransactionsToDB();
	if (!Network::isUninitialized()) {
	    Network::getInstance().broadcastTransaction(tx);
	}
	std::cout << "✅ Transaction broadcasted: " << from << " → " << to

                  << " (" << amount << " AlynCoin, metadata: " << metadata << ")\n";
    } else {
        std::cerr << "❌ Transaction signing failed.\n";
        return 1;
    }

    std::exit(0);
}
    // === DAO proposal submission ===
    if (argc >= 4 && std::string(argv[1]) == "dao-submit") {
        std::string from = argv[2];
        std::string desc = argv[3];
        ProposalType type = ProposalType::CUSTOM_ACTION;
        double amt = (argc >= 6) ? std::stod(argv[5]) : 0.0;
        std::string target = (argc >= 7) ? argv[6] : "";
        if (argc >= 5) type = static_cast<ProposalType>(std::stoi(argv[4]));

        Proposal prop;
        prop.proposal_id = Crypto::sha256(Crypto::generateRandomHex(16));
        prop.proposer_address = from;
        prop.description = desc;
        prop.type = type;
        prop.transfer_amount = amt;
        prop.target_address = target;
        prop.creation_time = std::time(nullptr);
        prop.deadline_time = prop.creation_time + 86400;
        prop.status = ProposalStatus::PENDING;

        if (DAO::createProposal(prop)) {
            std::cout << "✅ Proposal submitted. ID: " << prop.proposal_id << "\n";
        } else {
            std::cerr << "❌ Failed to submit proposal.\n";
        }
        std::exit(0);
    }

    // === DAO voting ===
    if (argc >= 5 && std::string(argv[1]) == "dao-vote") {
        std::string from = argv[2];
        std::string propID = argv[3];
        std::string vote = argv[4];
        bool yes = (vote == "yes" || vote == "y");

        Blockchain &b = Blockchain::getInstance();
        double weight = b.getBalance(from);
        if (DAO::castVote(propID, yes, static_cast<uint64_t>(weight))) {
            std::cout << "✅ Vote cast!\n";
        } else {
            std::cerr << "❌ Failed to vote.\n";
        }
        std::exit(0);
    }
  // === Transaction history ===
    if (cmd == "history" && argc >= 3) {
        std::string addr = argv[2];
    Blockchain &b = Blockchain::getInstance();
        std::cout << "🔍 Loading blockchain from DB...\n";
        b.loadFromDB();
        b.reloadBlockchainState();
        std::vector<Transaction> relevant;
        std::unordered_map<std::string, std::string> txType;
        std::unordered_set<std::string> seen;
        auto toLower = [](std::string s) {
            std::transform(s.begin(), s.end(), s.begin(), ::tolower);
            return s;
        };
        std::string addrLower = toLower(addr);
        auto blocks = b.getAllBlocks();
        for (const auto& blk : blocks) {
            std::string blockMiner = toLower(blk.getMinerAddress());
            double reward = blk.getReward();
            for (const auto& tx : blk.getTransactions()) {
                std::string hash = tx.getHash().empty() ? tx.getTransactionHash() : tx.getHash();
                if (!seen.count(hash) &&
                    (toLower(tx.getSender()) == addrLower || toLower(tx.getRecipient()) == addrLower)) {
                    relevant.push_back(tx);
                    txType[hash] = "L1";
                    seen.insert(hash);
                }
            }
            if (blockMiner == addrLower && reward > 0.0) {
                Transaction rewardTx = Transaction::createSystemRewardTransaction(
                    blk.getMinerAddress(), reward, blk.getTimestamp(), "mined_" + blk.getHash());
                std::string rewardHash = rewardTx.getHash();
                if (!seen.count(rewardHash)) {
                    relevant.push_back(rewardTx);
                    txType[rewardHash] = "Mined";
                    seen.insert(rewardHash);
                }
            }
        }
        auto rollups = b.getAllRollupBlocks();
        for (const auto& roll : rollups) {
            for (const auto& tx : roll.getTransactions()) {
                std::string hash = tx.getHash().empty() ? tx.getTransactionHash() : tx.getHash();
                if (!seen.count(hash) &&
                    (toLower(tx.getSender()) == addrLower || toLower(tx.getRecipient()) == addrLower)) {
                    relevant.push_back(tx);
                    txType[hash] = "L2";
                    seen.insert(hash);
                }
            }
        }
        auto allTxs = Transaction::loadAllFromDB();
        for (const auto& tx : allTxs) {
            std::string hash = tx.getHash().empty() ? tx.getTransactionHash() : tx.getHash();
            if (!seen.count(hash) &&
                (toLower(tx.getSender()) == addrLower || toLower(tx.getRecipient()) == addrLower)) {
                relevant.push_back(tx);
                txType[hash] = "L1";
                seen.insert(hash);
            }
        }
        std::sort(relevant.begin(), relevant.end(), [](const Transaction& a, const Transaction& b) {
            return a.getTimestamp() < b.getTimestamp();
        });
        std::cout << "\n=== Transaction History for: " << addr << " ===\n";
        std::cout << "📜 Found " << relevant.size() << " related transactions.\n\n";
        for (const auto& tx : relevant) {
            std::string hash = tx.getHash().empty() ? tx.getTransactionHash() : tx.getHash();
            std::string type = txType.count(hash) ? txType[hash] : "Unknown";
            time_t ts = tx.getTimestamp();
            std::tm* tmPtr = std::localtime(&ts);
            char timeStr[64];
            std::strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", tmPtr);
            std::cout << "🕒 " << timeStr << " [" << type << "]\n"
                    << "From: " << tx.getSender() << "\n"
                    << "To:   " << tx.getRecipient() << "\n"
                    << "💰 Amount: " << tx.getAmount() << " AlynCoin\n";
            if (!tx.getMetadata().empty()) std::cout << "📎 Metadata: " << tx.getMetadata() << "\n";
            std::cout << "🔑 TxHash: " << hash << "\n"
                    << "------------------------------\n";
        }
        return 0;
    }

	// === Recursive zk-STARK Proof by address (GUI / filtered) ===
	if (argc >= 5 && std::string(argv[1]) == "recursiveproof") {
	    std::string addr = argv[2];
	    int count = 0;
	    std::string outputFile;

	    for (int i = 3; i < argc; ++i) {
	        std::string arg = argv[i];
	        if (arg == "--last" && i + 1 < argc) {
	            try {
	                count = std::stoi(argv[++i]);
	            } catch (...) {
	                std::cerr << "❌ Invalid --last argument.\n";
	                return 1;
	            }
	        } else if (arg == "--out" && i + 1 < argc) {
	            outputFile = argv[++i];
	        }
	    }

	    if (addr.empty() || count <= 0) {
	        std::cerr << "❌ Invalid address or --last count.\n";
	        return 1;
	    }

	    Blockchain& b = getBlockchain();
	    b.loadFromDB();  // ensure block list is populated
	    b.reloadBlockchainState();

	    std::vector<std::string> hashes;
	    int selected = 0;

	    auto blocks = b.getAllBlocks();
	    for (auto it = blocks.rbegin(); it != blocks.rend() && selected < count; ++it) {
	        auto txs = it->getTransactions();
	        for (const auto& tx : txs) {
	            if (selected >= count) break;
	            if (tx.getSender() == addr || tx.getRecipient() == addr) {
	                hashes.push_back(tx.getHash());
	                selected++;
	            }
	        }
	    }

	    if (hashes.empty()) {
	        std::cout << "⚠️ No transactions found for " << addr << ".\n";
	        return 0;
	    }

	    std::string result = generateRecursiveProofToFile(hashes, addr, selected, outputFile);
	    std::cout << result << "\n";
	    return 0;
	}

    // === Mined block stats ===
    if (argc == 3 && std::string(argv[1]) == "mychain") {
        std::string addr = argv[2];
        Blockchain &b = Blockchain::getInstance();
        int count = 0;
        double reward = 0.0;
        for (const auto &blk : b.getAllBlocks()) {
            if (blk.getMinerAddress() == addr) {
                count++;
                reward += blk.getReward();
            }
        }
        std::cout << "📦 Blocks mined: " << count << "\n";
        std::cout << "💰 Total rewards: " << reward << " AlynCoin\n";
        std::exit(0);
    }

       // === CLI mining support ===
   if (argc == 3 && std::string(argv[1]) == "mine") {
     std::string minerAddr = argv[2];
     auto dil = Crypto::loadDilithiumKeys(minerAddr);
     auto fal = Crypto::loadFalconKeys(minerAddr);

     Blockchain &b = Blockchain::getInstance();
     Block mined = b.minePendingTransactions(minerAddr, dil.privateKey, fal.privateKey);

     if (mined.getHash().empty()) {
         std::cerr << "❌ Mining failed or returned empty block.\n";
         return 1;
     }

     b.saveToDB();
     std::cout << "✅ Block mined! Hash: " << mined.getHash() << "\n";
     std::exit(0);
 }

// === ROLLUP ===
if (argc >= 3 && std::string(argv[1]) == "rollup") {
    std::string walletAddr = argv[2];
    Blockchain& blockchain = getBlockchain();

    if (!blockchain.loadFromDB()) {
        std::cerr << "❌ Could not load blockchain from DB.\n";
        return 1;
    }

    blockchain.loadPendingTransactionsFromDB();
    std::vector<Transaction> allTxs = blockchain.getPendingTransactions();
    blockchain.setPendingL2TransactionsIfNotInRollups(allTxs);

    std::cout << "🔁 Generating Normal Rollup Block...\n";

    std::vector<Transaction> l2Transactions = blockchain.getPendingL2Transactions();
    if (l2Transactions.empty()) {
        std::cout << "⚠️ No pending L2 transactions to roll up.\n";
        return 0;
    }

    std::unordered_map<std::string, double> stateBefore = blockchain.getCurrentState();
    std::unordered_map<std::string, double> stateAfter =
        blockchain.simulateL2StateUpdate(stateBefore, l2Transactions);

    RollupBlock rollup(
        blockchain.getRollupChainSize(),
        blockchain.getLastRollupHash(),
        l2Transactions
    );

    std::string prevRecursive = blockchain.getLastRollupProof();
    rollup.generateRollupProof(stateBefore, stateAfter, prevRecursive);

    if (blockchain.isRollupBlockValid(rollup)) {
        blockchain.addRollupBlock(rollup);
	if (!Network::isUninitialized()) {
    	Network::getInstance().broadcastRollupBlock(rollup);
	}
        std::cout << "✅ Rollup Block created successfully!\n";
        std::cout << "📦 Rollup Hash: " << rollup.getHash() << "\n";
    } else {
        std::cerr << "❌ Rollup Block creation failed: Proof invalid.\n";
    }

    return 0;
}

// === RECURSIVE ROLLUP ===
if (argc >= 3 && std::string(argv[1]) == "recursive-rollup") {
    std::string walletAddr = argv[2];
    Blockchain& blockchain = getBlockchain();

    if (!blockchain.loadFromDB()) {
        std::cerr << "❌ Could not load blockchain from DB.\n";
        return 1;
    }

    blockchain.loadPendingTransactionsFromDB();
    std::vector<Transaction> allTxs = blockchain.getPendingTransactions();
    blockchain.setPendingL2TransactionsIfNotInRollups(allTxs);

    std::cout << "🔁 Generating Rollup Block with Recursive zk-STARK Proof...\n";

    std::vector<Transaction> l2Transactions = blockchain.getPendingL2Transactions();
    if (l2Transactions.empty()) {
        std::cout << "⚠️ No pending L2 transactions to roll up.\n";
        return 0;
    }

    std::unordered_map<std::string, double> stateBefore = blockchain.getCurrentState();
    std::unordered_map<std::string, double> stateAfter =
        blockchain.simulateL2StateUpdate(stateBefore, l2Transactions);

    RollupBlock rollup(
        blockchain.getRollupChainSize(),
        blockchain.getLastRollupHash(),
        l2Transactions
    );

    std::string prevRecursive = blockchain.getLastRollupProof();
    rollup.generateRollupProof(stateBefore, stateAfter, prevRecursive);

    if (blockchain.isRollupBlockValid(rollup)) {
        blockchain.addRollupBlock(rollup);
	if (!Network::isUninitialized()) {
	    Network::getInstance().broadcastRollupBlock(rollup);
	}
        std::cout << "✅ Recursive Rollup Block created successfully!\n";
        std::cout << "📦 Rollup Hash: " << rollup.getHash() << "\n";
    } else {
        std::cerr << "❌ Recursive Rollup Block creation failed: Proof invalid.\n";
    }

    return 0;
}

			// NFT SPACE //

// Mint  NFT
if (cmd == "nft-mint" && argc >= 5) {
    std::string creator = argv[2];
    std::string metadata = argv[3];
    std::string imageHash = argv[4];
    std::string identity = (argc >= 6) ? argv[5] : "";

    std::string privKeyPath = DBPaths::getKeyDir() + creator + "_private.pem";
    if (!std::filesystem::exists(privKeyPath)) {
        std::cerr << "❌ Missing private key file for wallet: " << privKeyPath << "\n";
        return 1;
    }

    int64_t ts = std::time(nullptr);
    std::string id = generateNFTID(creator, imageHash, ts);
    std::string message = id + creator + creator + metadata + imageHash + std::to_string(ts);
    auto msgHash = Crypto::sha256ToBytes(message);
    auto keypair = Crypto::loadFalconKeys(creator);

    std::vector<uint8_t> sig = Crypto::signWithFalcon(msgHash, keypair.privateKey);

    NFT nft{id, creator, creator, metadata, imageHash, ts, sig};
    nft.creator_identity = identity;
    nft.generateZkStarkProof();

    if (!nft.submitMetadataHashTransaction()) {
        std::cerr << "❌ Metadata transaction failed.\n";
        return 1;
    }

    if (!nft.verifySignature() || !NFTStorage::saveNFT(nft, blockchain.getRawDB())) {
        std::cerr << "❌ Failed to verify or save NFT.\n";
        return 1;
    }

    std::cout << "✅ NFT minted! ID: " << id << "\n";
    return 0;
}

// Transfer NFT
if (cmd == "nft-transfer" && argc >= 4) {
    std::string nftID = argv[2];
    std::string newOwner = argv[3];
    NFT nft;
    if (!NFTStorage::loadNFT(nftID, nft, blockchain.getRawDB())) {
        std::cerr << "❌ NFT not found.\n";
        return 1;
    }

    std::string current = getLoadedWalletAddress();
    if (nft.owner != current || nft.revoked) {
        std::cerr << "❌ Not the owner or NFT is revoked.\n";
        return 1;
    }

    nft.transferHistory.push_back(current);
    nft.owner = newOwner;
    nft.timestamp = std::time(nullptr);

    std::string message = nft.getSignatureMessage();
    auto msgHash = Crypto::sha256ToBytes(message);
    auto keypair = Crypto::loadFalconKeys(current);
    nft.signature = Crypto::signWithFalcon(msgHash, keypair.privateKey);

    if (!nft.verifySignature() || !NFTStorage::saveNFT(nft, blockchain.getRawDB())) {
        std::cerr << "❌ Failed to verify or save transfer.\n";
        return 1;
    }

    std::cout << "✅ NFT transferred.\n";
    return 0;
}
//Re-mint NFT (Update Metadata)
if (cmd == "nft-remint" && argc >= 5) {
    std::string id = argv[2];
    std::string newMetadata = argv[3];
    std::string reason = argv[4];

    std::string currentUser;
    if (argc >= 6) {
        currentUser = argv[5];  // passed by GUI
    } else {
        currentUser = getLoadedWalletAddress();  // fallback for CLI
    }

    if (currentUser.empty()) {
        std::cerr << "❌ No wallet loaded. Please load a wallet or pass address.\n";
        return 1;
    }

    NFT nft;
    if (!NFTStorage::loadNFT(id, nft, blockchain.getRawDB())) {
        std::cerr << "❌ NFT not found.\n";
        return 1;
    }

    if (nft.owner != currentUser || nft.revoked) {
        std::cerr << "❌ You are not the owner of this NFT or it is revoked.\n";
        return 1;
    }

    int newVersion = 1;
    if (!nft.version.empty()) {
        try { newVersion = std::stoi(nft.version) + 1; } catch (...) { newVersion = 1; }
    }

    int64_t ts = std::time(nullptr);
    std::string newId = generateNFTID(currentUser, nft.imageHash, ts);
    std::string message = newId + currentUser + currentUser + newMetadata + nft.imageHash + std::to_string(ts);
    auto msgHash = Crypto::sha256ToBytes(message);
    auto keys = Crypto::loadFalconKeys(currentUser);
    std::vector<uint8_t> sig = Crypto::signWithFalcon(msgHash, keys.privateKey);

    NFT updated{newId, currentUser, currentUser, newMetadata, nft.imageHash, ts, sig};
    updated.version = std::to_string(newVersion);
    updated.creator_identity = nft.creator_identity;
    updated.expiry_timestamp = nft.expiry_timestamp;
    updated.previous_versions = nft.previous_versions;
    updated.previous_versions.push_back(nft.id);

    updated.generateZkStarkProof();

    std::string rehash = Crypto::sha256(updated.metadata + updated.imageHash + updated.version);
    if (!submitMetadataHashTransaction(rehash, currentUser, "falcon", true)) {
        std::cerr << "❌ Metadata transaction failed.\n";
        return 1;
    }

    if (!updated.verifySignature() || !NFTStorage::saveNFT(updated, blockchain.getRawDB())) {
        std::cerr << "❌ Failed to verify or save updated NFT.\n";
        return 1;
    }

    std::cout << "✅ NFT re-minted successfully! New ID: " << newId << "\n";
    return 0;
}
//Export NFT to File
if (cmd == "nft-export" && argc >= 3) {
    std::string id = argv[2];
    NFT nft;
    if (!NFTStorage::loadNFT(id, nft, blockchain.getRawDB())) {
        std::cerr << "❌ Not found.\n";
        return 1;
    }
    nft.exportToFile();
    return 0;
}
// Encrypt Metadata (AES-256)
if (cmd == "nft-encrypt" && argc >= 5) {
    std::string id = argv[2];
    std::string plaintext = argv[3];
    std::string password = argv[4];
    NFT nft;
    if (!NFTStorage::loadNFT(id, nft, blockchain.getRawDB())) {
        std::cerr << "❌ NFT not found.\n";
        return 1;
    }
    nft.encrypted_metadata = AES::encrypt(plaintext, password);
    NFTStorage::saveNFT(nft, blockchain.getRawDB());
    std::cout << "✅ Encrypted metadata stored.\n";
    return 0;
}

// Decrypt Metadata (AES-256)
if (cmd == "nft-decrypt" && argc >= 4) {
    std::string id = argv[2];
    std::string password = argv[3];
    NFT nft;
    if (!NFTStorage::loadNFT(id, nft, blockchain.getRawDB())) {
        std::cerr << "❌ NFT not found.\n";
        return 1;
    }
    if (nft.encrypted_metadata.empty()) {
        std::cout << "⚠️ No encrypted metadata found for this NFT.\n";
        return 0;
    }
    try {
        std::string decrypted = AES::decrypt(nft.encrypted_metadata, password);
        std::cout << "🔓 Decrypted metadata:\n" << decrypted << "\n";
    } catch (const std::exception& e) {
        std::cerr << "❌ Decryption failed: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

//  NFT Stats
if (cmd == "nft-stats") {
    auto all = NFTStorage::loadAllNFTs(blockchain.getRawDB());
    std::string me = getLoadedWalletAddress();

    if (me.empty()) {
        std::cout << "⚠️ No wallet loaded. Please enter your wallet address manually: ";
        std::getline(std::cin, me);
    }

    int total = 0, mine = 0, zk = 0;
    std::map<std::string, int> typeCount;

    for (const auto& nft : all) {
        ++total;
        if (!me.empty() && nft.owner == me) ++mine;
        if (!nft.zkStarkProof.empty()) ++zk;
        if (!nft.nft_type.empty()) typeCount[nft.nft_type]++;
    }

    std::string topType = "N/A";
    int max = 0;
    for (auto& [type, count] : typeCount) {
        if (count > max) {
            max = count;
            topType = type;
        }
    }

    std::cout << "\n📊 NFT Stats:\n";
    std::cout << "Total: " << total << "\n";
    std::cout << "Mine: " << (me.empty() ? "N/A (no wallet provided)" : std::to_string(mine)) << "\n";
    std::cout << "zk-STARK: " << zk << "\n";
    std::cout << "Most Common Type: " << topType << "\n";
    return 0;
}
// View All NFTs / My NFTs
if (cmd == "nft-my") {
    std::string current = argc >= 3 ? argv[2] : getLoadedWalletAddress();
    if (current.empty()) {
        std::cerr << "❌ No wallet loaded. Please ensure current_wallet.txt is set or pass wallet as argument.\n";
        return 1;
    }
    auto all = NFTStorage::loadAllNFTs(blockchain.getRawDB());
    for (const auto& nft : all) {
        if (nft.owner == current) {
            std::cout << nft.toJSON() << "\n\n";
        }
    }
    return 0;
}
if (cmd == "nft-all") {
    auto all = NFTStorage::loadAllNFTs(blockchain.getRawDB());
    for (const auto& nft : all) {
        std::cout << nft.toJSON() << "\n\n";
    }
    return 0;
}
// Verify Image/File Hash (NFT authenticity check)
if (cmd == "nft-verifyhash" && argc >= 3) {
    std::string filepath = argv[2];
    std::ifstream file(filepath, std::ios::binary);
    if (!file) {
        std::cerr << "❌ File not found: " << filepath << "\n";
        return 1;
    }
    std::ostringstream buffer;
    buffer << file.rdbuf();
    std::string contents = buffer.str();
    std::string fileHash = Crypto::sha256(contents);

    auto all = NFTStorage::loadAllNFTs(blockchain.getRawDB());
    for (const auto& nft : all) {
        if (nft.imageHash == fileHash) {
            std::cout << "✅ NFT found for file!\n" << nft.toJSON() << "\n";
            return 0;
        }
    }
    std::cout << "❌ No NFT found matching the file hash.\n";
    return 1;
}



     // ================= CLI COMMAND HANDLERS END ===================
    if (network) {
        network->run();
    }

    if (network && !connectIP.empty()) {
        std::string ip;
        short connectPort;
        if (connectIP.find(":") != std::string::npos) {
            size_t colon = connectIP.find(":");
            ip = connectIP.substr(0, colon);
            connectPort = std::stoi(connectIP.substr(colon + 1));
        } else {
            ip = connectIP;
            connectPort = 15671;
        }

        // 🌐 Attempt peer connection
        network->connectToPeer(ip, connectPort);
        std::this_thread::sleep_for(std::chrono::milliseconds(300));

        // 📡 Reconnect self to allow reverse sync
        network->connectToPeer("127.0.0.1", port);
        std::this_thread::sleep_for(std::chrono::milliseconds(300));

        // 🔄 Trigger sync now that connection is open
        std::cout << "🔁 Triggering sync after peer connect...\n";
        network->syncWithPeers();
        if (blockchain.getHeight() <= 1) {
            std::cout << "🔄 [Cold Sync] Attempting to load chain from peers...\n";
            blockchain.loadFromPeers();
        }
    } else if (network) {
        // No explicit --connect, still try syncing
        network->syncWithPeers();
        if (blockchain.getHeight() <= 1) {
            std::cout << "🔄 [Cold Sync] Attempting to load chain from peers...\n";
            blockchain.loadFromPeers();
        }
    }
    std::this_thread::sleep_for(std::chrono::seconds(2));

    PeerManager *peerManager = network ? network->getPeerManager() : nullptr;
    SelfHealingNode healer(&blockchain, peerManager);

    std::thread autoHealThread([&]() {
        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(30));
            std::cout << "\n🩺 [Auto-Heal] Running periodic health monitor...\n";
            healer.monitorAndHeal();
        }
    });
    autoHealThread.detach();

    std::string minerAddress;
    bool running = true;

    while (running) {
        std::cout << "\n=== AlynCoin Node CLI ===\n";
        std::cout << "1. Add Transaction\n";
        std::cout << "2. Mine Block\n";
        std::cout << "3. Print Blockchain\n";
        std::cout << "4. Start Mining Loop\n";
        std::cout << "5. Sync Blockchain\n";
        std::cout << "6. View Dev Fund Info\n";
        std::cout << "7. Check Balance\n";
        std::cout << "8. Generate Rollup Block\n";
        std::cout << "9. Exit\n";
        std::cout << "10. Run Self-Heal Now 🩺\n";
        std::cout << "Choose an option: ";

        int choice;
        std::cin >> choice;
        if (std::cin.fail()) {
            clearInputBuffer();
            std::cout << "Invalid input!\n";
            continue;
        }

        switch (choice) {
        case 1: {
            std::string sender, recipient;
            double amount;
            std::cout << "Enter sender: ";
            std::cin >> sender;
            std::cout << "Enter recipient: ";
            std::cin >> recipient;
            std::cout << "Enter amount: ";
            std::cin >> amount;

            Crypto::ensureUserKeys(sender);
            DilithiumKeyPair dilKeys = Crypto::loadDilithiumKeys(sender);
            FalconKeyPair falKeys = Crypto::loadFalconKeys(sender);

            Transaction tx(sender, recipient, amount, "", "", time(nullptr));
            tx.signTransaction(dilKeys.privateKey, falKeys.privateKey);

            // 🚫 Prevent duplicate in pending transactions
            bool duplicate = false;
            for (const auto& existing : blockchain.getPendingTransactions()) {
                if (existing.getSender() == tx.getSender() &&
                    existing.getRecipient() == tx.getRecipient() &&
                    existing.getAmount() == tx.getAmount() &&
                    existing.getMetadata() == tx.getMetadata()) {
                    std::cout << "⚠️ Duplicate transaction already exists in mempool.\n";
                    duplicate = true;
                    break;
                }
            }
            if (duplicate) break;

            if (!tx.isValid(Crypto::toHex(dilKeys.publicKey), Crypto::toHex(falKeys.publicKey))) {
                std::cout << "❌ Invalid transaction (signature check failed).\n";
                break;
            }

            blockchain.addTransaction(tx);
            if (network) network->broadcastTransaction(tx);
            std::cout << "✅ Transaction added and broadcasted.\n";
            break;
        }

        case 2: {
            std::cout << "Enter miner address: ";
            std::cin >> minerAddress;
            Block mined = blockchain.mineBlock(minerAddress);
            if (!mined.getHash().empty()) {
                blockchain.saveToDB();
                blockchain.savePendingTransactionsToDB();
                if (network) network->broadcastBlock(mined);
                blockchain.reloadBlockchainState();
                std::cout << "✅ Block mined and broadcasted.\n";
            }
            break;
        }

        case 3:
            blockchain.printBlockchain();
            break;

        case 4:
            std::cout << "Enter miner address: ";
            std::cin >> minerAddress;
            Miner::startMiningProcess(minerAddress);
            break;

        case 5:
            if (network) {
                network->scanForPeers();
                network->requestPeerList();
                network->intelligentSync();
            }
            break;

        case 6:
            std::cout << "Dev Fund Balance: " << blockchain.getBalance("DevFundWallet") << " AlynCoin\n";
            break;

        case 7: {
            std::string addr;
            std::cout << "Enter address: ";
            std::cin >> addr;
            std::cout << "Balance: " << blockchain.getBalance(addr) << " AlynCoin\n";
            break;
        }

        case 8: {
            blockchain.loadPendingTransactionsFromDB();
            auto allTxs = blockchain.getPendingTransactions();
            blockchain.setPendingL2TransactionsIfNotInRollups(allTxs);
            auto l2Transactions = blockchain.getPendingL2Transactions();
            if (l2Transactions.empty()) {
                std::cout << "⚠️ No pending L2 transactions to roll up.\n";
                break;
            }
            auto stateBefore = blockchain.getCurrentState();
            auto stateAfter = blockchain.simulateL2StateUpdate(stateBefore, l2Transactions);
            RollupBlock rollup(
                blockchain.getRollupChainSize(),
                blockchain.getLastRollupHash(),
                l2Transactions);
            std::string prevRecursive = blockchain.getLastRollupProof();
            rollup.generateRollupProof(stateBefore, stateAfter, prevRecursive);
            if (blockchain.isRollupBlockValid(rollup)) {
                blockchain.addRollupBlock(rollup);
                if (network) network->broadcastRollupBlock(rollup);
                std::cout << "✅ Rollup Block created. Hash: " << rollup.getHash() << "\n";
            } else {
                std::cout << "❌ Rollup Block creation failed.\n";
            }
            break;
        }

        case 9:
            std::cout << "Shutting down AlynCoin Node...\n";
            running = false;
            break;

        case 10:
            std::cout << "🩺 Manually triggering self-healing check...\n";
            healer.monitorAndHeal();
            break;

        default:
            std::cout << "Invalid choice!\n";
        }
    }

    return 0;
}
