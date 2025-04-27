#ifndef MINING_H
#define MINING_H

#include "block.h"
#include "blockchain.h"
#include "difficulty.h" // LWMA-based difficulty adjustment
#include <string>

// ✅ **Compute BLAKE3 hash for mining**
std::string calculateBLAKE3Hash(const std::string &input);

// ✅ **Mine a block using BLAKE3**
void mineBlock(Block &block, int difficulty);

// ✅ **Parallel mining with multiple threads**
void parallelMine(Block &block, int difficulty);

// ✅ **Calculate the next difficulty using LWMA**
int getNextDifficulty(const Blockchain &chain);

// ✅ **Validate checkpoint every 100 blocks**
bool isCheckpointValid(const Blockchain &chain, int blockIndex,
                       std::string expectedHash);

#endif // MINING_H
