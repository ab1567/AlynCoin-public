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

// 🔍 Helper: Estimate number of connected miners (same as before)
inline int getActiveMinerCount() {
    std::lock_guard<std::timed_mutex> lk(peersMutex);
    return std::max(1, static_cast<int>(peerTransports.size()));
}

/*
 * AlynCoin Dynamic Difficulty — LWMA-120
 * - Uses 120-block Linearly Weighted Moving Average for block interval
 * - ±2x clamp per retarget to avoid run-away or time-warp
 * - Gentle scaling with supply and miner count
 * - Target block time: 60 seconds
 */
inline uint64_t calculateSmartDifficulty(const Blockchain& chain)
{
    constexpr int    WINDOW         = 120;      // LWMA window size
    constexpr double TARGET_SPACING = 60.0;     // Target block time (s)
    constexpr double MAX_UP         = 2.0;      // max 2x per window
    constexpr double MAX_DOWN       = 0.5;      // min 0.5x per window
    constexpr double TOTAL_SUPPLY   = 100'000'000.0;

    size_t height = chain.getBlockCount();
    if (height < 2) return 1; // not enough data

    int N = static_cast<int>(std::min<size_t>(WINDOW, height - 1));
    double sumWeighted = 0.0;
    double sumWeights  = 0.0;

    // Calculate LWMA over last N blocks
    for (int i = 1; i <= N; ++i) {
        const auto& cur  = chain.getChain()[height - i];
        const auto& prev = chain.getChain()[height - i - 1];
        double delta = std::max<double>(1.0, cur.getTimestamp() - prev.getTimestamp());
        sumWeighted += i * delta;
        sumWeights  += i;
    }

    double lwma_interval = sumWeighted / sumWeights;
    double prevDiff = chain.getLatestBlock().difficulty;
    double factor   = TARGET_SPACING / lwma_interval;
    factor          = std::clamp(factor, MAX_DOWN, MAX_UP);

    double nextDiff = prevDiff * factor;

    // Gentle supply-based scaling (linear, not exponential)
    double supplyRatio = std::clamp(chain.getTotalSupply() / TOTAL_SUPPLY, 0.0, 1.0);
    nextDiff *= (1.0 + supplyRatio); // at max supply, 2x harder

    // Miner count scaling (small, capped at 3x)
    double minerFactor = 1.0 + getActiveMinerCount() / 100.0; // +1% per miner
    nextDiff *= std::min(minerFactor, 3.0);

    // Clamp to [1, ...]
    return static_cast<uint64_t>(std::max<double>(1.0, nextDiff));
}

#endif // DIFFICULTY_H
