#include "blake3.h"
#include "block.h"
#include "blockchain.h"
#include "difficulty.h"  // LWMA-based difficulty adjustment
#include <iostream>
#include <thread>
#include <vector>
#include <chrono>
#include <random>

const int NUM_THREADS = std::thread::hardware_concurrency();

std::string calculateBLAKE3Hash(const std::string& input) {
    uint8_t hash[BLAKE3_OUT_LEN];
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, input.data(), input.size());
    blake3_hasher_finalize(&hasher, hash, BLAKE3_OUT_LEN);
    return std::string(reinterpret_cast<char*>(hash), BLAKE3_OUT_LEN);
}

void mineBlock(Block& block, int difficulty) {
    std::string target(difficulty, '0');
    std::string hash;

    while (true) {
        block.setNonce(block.getNonce() + 1);
        hash = calculateBLAKE3Hash(block.getHashInput());

        if (hash.substr(0, difficulty) == target) {
            block.setHash(hash);
            break;
        }
    }

    std::cout << "⛏️ Block mined: " << block.getHash() << std::endl;
}

void parallelMine(Block& block, int difficulty) {
    std::vector<std::thread> workers;
    bool found = false;

    for (int i = 0; i < NUM_THREADS; i++) {
        workers.emplace_back([&]() {
            while (!found) {
                Block candidate = block;
                candidate.setNonce(rand());
                std::string hash = calculateBLAKE3Hash(candidate.getHashInput());

                if (hash.substr(0, difficulty) == std::string(difficulty, '0')) {
                    block = candidate;
                    found = true;
                }
            }
        });
    }

    for (auto& worker : workers) {
        worker.join();
    }

    std::cout << "⛏️ Parallel block mined: " << block.getHash() << std::endl;
}

// ✅ **LWMA-based adaptive difficulty adjustment**
int getNextDifficulty(const Blockchain& chain) {
    return LWMA_calculate_difficulty(chain);
}

// ✅ **Checkpointing to prevent 51% attacks**
bool isCheckpointValid(const Blockchain& chain, int blockIndex, std::string expectedHash) {
    if (blockIndex % 100 == 0) {
        return chain.getBlock(blockIndex).getHash() == expectedHash;
    }
    return true;
}
