#include "generated/block_protos.pb.h"
#include "generated/sync_protos.pb.h"
#include "miner.h"
#include "blake3.h"
#include "blockchain.h"
#include "crypto_utils.h"
#include "mining.h"
#include <atomic>
#include "network.h"
#include <chrono>
#include <fstream>
#include <iostream>
#include <thread>

std::atomic<bool> miningActive{false};

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

        if (!miningActive.exchange(true)) {
            Blockchain &blockchain = Blockchain::getInstance(8333, DBPaths::getBlockchainDB(), true);

            while (miningActive) {
                blockchain.loadPendingTransactionsFromDB();
                blockchain.reloadBlockchainState();

                Block minedBlock = blockchain.mineBlock(minerAddress);

                if (minedBlock.getHash().empty()) {
quietPrint( "❌ Mining failed. No valid hash generated." << std::endl);
                    miningActive = false;
                    break;
                }

                std::string blockMsg = minedBlock.getHash() + minedBlock.getPreviousHash() +
                                       minedBlock.getTransactionsHash() + std::to_string(minedBlock.getTimestamp());

                std::vector<unsigned char> pubKeyDil(minedBlock.getPublicKeyDilithium().begin(),
                                                     minedBlock.getPublicKeyDilithium().end());
                std::vector<unsigned char> pubKeyFal(minedBlock.getPublicKeyFalcon().begin(),
                                                     minedBlock.getPublicKeyFalcon().end());

quietPrint( "[SIGN DEBUG] 🔏 Block Message (MINING): " << blockMsg << std::endl);
quietPrint( "[SIGN DEBUG] 🧬 Dilithium PubKey (MINING): " << Crypto::toHex(pubKeyDil) << std::endl);
quietPrint( "[SIGN DEBUG] 🧬 Falcon PubKey (MINING): " << Crypto::toHex(pubKeyFal) << std::endl);

                blockchain.addBlock(minedBlock);
                blockchain.saveToDB();

                // ✅ ✅ NEW: Broadcast mined block to live peers
                Network::getInstance(8333, &blockchain, nullptr).broadcastBlock(minedBlock);
                std::cout << "✅ Block mined and broadcasted.\n";

                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }
    } catch (const std::exception &e) {
quietPrint( "❌ Fatal error: " << e.what() << std::endl);
    }
}

// ✅ Improved Mining Algorithm: Hybrid PoW (BLAKE3 + Keccak256)
std::string Miner::mineBlock(int difficulty) {
    std::string lastHash = Blockchain::getInstance(8333, DBPaths::getBlockchainDB(), true).getLatestBlock().getHash();
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
