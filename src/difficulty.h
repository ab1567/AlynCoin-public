// File: src/difficulty.h

#ifndef DIFFICULTY_H
#define DIFFICULTY_H

#include "blockchain.h"
#include <vector>
#include <numeric>

// LWMA Difficulty Algorithm Implementation
inline int LWMA_calculate_difficulty(const Blockchain& chain) {
    const int N = 60; // Number of blocks to average
    if (chain.getBlockCount() < N) {
        return 1; // Minimum difficulty
    }
    
    std::vector<int> timestamps;
    std::vector<int> difficulties;
    
    for (int i = chain.getBlockCount() - N; i < chain.getBlockCount(); i++) {
        timestamps.push_back(chain.getChain()[i].getTimestamp());
        difficulties.push_back(chain.getChain()[i].difficulty);
    }
    
    int sumWeightedTime = 0;
    int sumDifficulty = std::accumulate(difficulties.begin(), difficulties.end(), 0);
    
    for (int i = 1; i < N; i++) {
        int weightedTime = timestamps[i] - timestamps[i - 1];
        sumWeightedTime += weightedTime * i; // More weight for newer blocks
    }
    
    int adjustedDifficulty = (sumDifficulty * N) / (2 * sumWeightedTime);
    return std::max(1, adjustedDifficulty); // Ensure difficulty never drops below 1
}

#endif // DIFFICULTY_H
