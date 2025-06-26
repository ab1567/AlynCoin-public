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
 * AlynCoin Dynamic Difficulty — LWMA-180 with supply ladder
 * - Uses a 180-block Linearly Weighted Moving Average
 * - Digishield-style clamps to smooth swings
 * - Difficulty floor ratchets up every 10 M supply
 * - Target block time: 60 seconds
 */
inline uint64_t calculateSmartDifficulty(const Blockchain& chain)
{
    constexpr int    LWMA_N         = 180;      // 3 hours of blocks
    constexpr double TARGET         = 60.0;     // 1 min block time
    constexpr double MAX_UP         = 1.8;      // Digishield dampening
    constexpr double MAX_DOWN       = 0.7;
    constexpr double DIFF_FLOOR_INC = 1.30;     // floor multiplier per 10M
    constexpr uint64_t GENESIS_DIFF = 1;

    const size_t h = chain.getBlockCount();
    if (h < 2) return GENESIS_DIFF;

    // ── dynamic floor ─────────────────────────────
    const uint64_t floor = static_cast<uint64_t>(
        std::pow(DIFF_FLOOR_INC,
                 static_cast<int>(chain.getTotalSupply() / 10'000'000)));

    // ── LWMA-180 (weighted) ───────────────────────
    const int  N = std::min<int>(LWMA_N, h - 1);
    long double sumW = 0, sumD = 0;
    for (int i = 1; i <= N; ++i) {
        const auto& cur  = chain.getChain()[h - i];
        const auto& prev = chain.getChain()[h - i - 1];
        long double solvetime = std::max<long double>(1,
            cur.getTimestamp() - prev.getTimestamp());
        sumW += i;
        sumD += i * solvetime;
    }

    long double lwma = sumD / sumW;
    long double adjust = TARGET / lwma;
    adjust = std::clamp(adjust,
                        static_cast<long double>(MAX_DOWN),
                        static_cast<long double>(MAX_UP));

    uint64_t next = std::max<uint64_t>(floor,
        static_cast<uint64_t>(chain.getLatestBlock().difficulty * adjust));
    return std::max<uint64_t>(1, next);
}

#endif // DIFFICULTY_H
