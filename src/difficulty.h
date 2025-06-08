#ifndef DIFFICULTY_H
#define DIFFICULTY_H

#include "blockchain.h"
#include <numeric>
#include <vector>
#include <iostream>
#include <cmath>
#include <algorithm>
#include <memory>
#include <mutex>
#include <boost/asio.hpp>
#include "transport/transport.h"
#include "transport/peer_globals.h"

// 🔍 Helper: Estimate number of connected miners
inline int getActiveMinerCount() {
    std::lock_guard<std::timed_mutex> lk(peersMutex);
    return std::max(1, static_cast<int>(peerTransports.size()));
}

// 🚀 Unstoppable Difficulty Scaling for AlynCoin
inline uint64_t calculateSmartDifficulty(const Blockchain &chain) {
    const int N = 120; // LWMA window
    if (chain.getBlockCount() < N)
        return 1;

    std::vector<int> timestamps;
    std::vector<int> difficulties;

    for (int i = chain.getBlockCount() - N; i < chain.getBlockCount(); ++i) {
        timestamps.push_back(chain.getChain()[i].getTimestamp());
        difficulties.push_back(chain.getChain()[i].difficulty);
    }

    int sumWeightedTime = 0;
    uint64_t sumDifficulty = std::accumulate(difficulties.begin(), difficulties.end(), uint64_t(0));

    for (int i = 1; i < N; ++i) {
        int delta = timestamps[i] - timestamps[i - 1];
        if (delta < 1) delta = 1;
        sumWeightedTime += delta * i;
    }

    if (sumWeightedTime == 0) return 1;

    uint64_t lwma = std::max(uint64_t(1), (sumDifficulty * N) / (2 * sumWeightedTime));

    // 📈 Difficulty scales with circulating supply (exponential curve)
    double supply = chain.getTotalSupply();
    const double totalSupply = 100000000.0;

    double supplyRatio = std::clamp(supply / totalSupply, 0.0, 1.0);
    double exponentialCurve = std::pow(1.0 + supplyRatio * 100.0, 2.5); // Non-linear growth

    // 👥 Miner count adjustment
    int miners = getActiveMinerCount();
    double minerFactor = std::min(1.0 + (miners / 50.0), 3.0); // Max 3x boost

    // 🔐 Final unstoppable difficulty
    uint64_t finalDifficulty = static_cast<uint64_t>(lwma * exponentialCurve * minerFactor);
    return std::max<uint64_t>(1, finalDifficulty);
}

#endif // DIFFICULTY_H
