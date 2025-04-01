#include "generated/block_protos.pb.h"
#include "generated/sync_protos.pb.h"
#include "miner.h"
#include "blake3.h"
#include "blockchain.h"
#include "crypto_utils.h"
#include "mining.h"
#include <atomic>
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

        // If miningActive was false, we set it to true. If it was already true, we do not start again.
        if (!miningActive.exchange(true)) {
            Blockchain &blockchain = Blockchain::getInstance(8333);

            while (miningActive) {
                // Reload chain & pending TX from DB so we see any newly added transactions
                blockchain.reloadBlockchainState();
                // We no longer check if pendingTx is empty, so we always attempt to mine a block
                // If no user transactions, mineBlock() will create an empty block with the reward
                Block minedBlock = blockchain.mineBlock(minerAddress);

                // If the block’s hash is empty, it means the call returned a failure
                if (minedBlock.getHash().empty()) {
                    std::cerr << "❌ Mining failed. No valid hash generated." << std::endl;
                    miningActive = false;
                    break;
                }

                // Attempt to add the newly mined block to the chain
                blockchain.addBlock(minedBlock);
                blockchain.saveToDB();
                std::cout << "✅ Block mined successfully!" << std::endl;

                // Optional: Sleep briefly between blocks to avoid overloading CPU
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }
    } catch (const std::exception &e) {
        std::cerr << "❌ Fatal error: " << e.what() << std::endl;
    }
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
