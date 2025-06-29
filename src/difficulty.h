#ifndef DIFFICULTY_H
#define DIFFICULTY_H

#include "blockchain.h"
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <mutex>
#include <boost/asio.hpp>
#include "transport/transport.h"
#include "transport/peer_globals.h"

// ===========================================================================
//  AlynCoin Monetary Base
//  --------------------------------------------------------------------------
//  • Premine: 10,000,000 ALYN minted in the genesis block (height = 0).
//    These coins are *already counted* in chain.getTotalSupply().
//  • Max supply: 100,000,000 ALYN
// ===========================================================================

constexpr uint64_t PREMINE_SUPPLY = 10'000'000;   // For clarity in docs/tests

// ─────────────────────────────────────────────────────────────────────────────
//  Helper: how many peers are actually submitting shares?
// ─────────────────────────────────────────────────────────────────────────────
inline int getActiveMinerCount()
{
    std::lock_guard<std::timed_mutex> lk(peersMutex);
    return std::max(1, static_cast<int>(peerTransports.size()));
}

// ─────────────────────────────────────────────────────────────────────────────
//  Difficulty ladder – user-friendly, piece-wise floor
//
//  Coins in circulation  |  Floor multiplier (× current diff)
//  ──────────────────────┼──────────────────────────────────
//    < 15 000 000  (includes 10 M premine) | 1.00   ← easy CPU tier
//    15 M – 19.9 M                         | 1.25
//    20 M – 29.9 M                         | 1.50
//    30 M – 49.9 M                         | 2.00
//    50 M – 79.9 M                         | 3.00
//    ≥ 80 M                                | 4.00   ← “serious-rig” era
// ─────────────────────────────────────────────────────────────────────────────
//
//  Retarget algorithm: LWMA-180 (≈3 hours worth of blocks) with
//  Digishield-style dampening so large hash-rate swings don’t shock the chain.
// ─────────────────────────────────────────────────────────────────────────────
inline uint64_t calculateSmartDifficulty(const Blockchain& chain)
{
    /* --- tweakables --- */
    constexpr int    LWMA_N     = 180;      // sample window (blocks)
    constexpr double TARGET     = 60.0;     // seconds / block
    constexpr double MAX_UP     = 1.8;      // +80 % / window
    constexpr double MAX_DOWN   = 0.6;      // –40 % / window
    constexpr uint64_t GENESIS_DIFF = 1;

    const size_t height = chain.getBlockCount();
    if (height < 2) return GENESIS_DIFF;

    // ── 1) difficulty floor from supply ladder ────────────────────────────
    const double supply = static_cast<double>(chain.getTotalSupply());
    double floorMult = 1.0;
    if      (supply >= 80'000'000) floorMult = 4.0;
    else if (supply >= 50'000'000) floorMult = 3.0;
    else if (supply >= 30'000'000) floorMult = 2.0;
    else if (supply >= 20'000'000) floorMult = 1.50;
    else if (supply >= 15'000'000) floorMult = 1.25;
    // else 1.00

    // ── 2) LWMA-N retarget ────────────────────────────────────────────────
    const int  N = std::min<int>(LWMA_N, height - 1);
    long double sumW = 0.0, sumD = 0.0;

    for (int i = 1; i <= N; ++i)
    {
        const auto& cur  = chain.getChain()[height - i];
        const auto& prev = chain.getChain()[height - i - 1];

        long double solvetime = std::max<long double>(1,
                             cur.getTimestamp() - prev.getTimestamp());

        sumW += i;                 // linear weight
        sumD += i * solvetime;     // weighted solve-times
    }

    const long double lwma    = sumD / sumW;
    long double factor        = TARGET / lwma;
    factor = std::clamp(factor,
                        static_cast<long double>(MAX_DOWN),
                        static_cast<long double>(MAX_UP));

    /* apply network-size nudging: +0.5 % diff per active miner, cap ×2 */
    const double minerFactor  = std::min(2.0,
                               1.0 + getActiveMinerCount() / 200.0);

    const long double rawNext = chain.getLatestBlock().difficulty * factor;
    const long double floored = std::max<long double>(floorMult, rawNext);

    return static_cast<uint64_t>(std::max<long double>(1.0,
                                floored * minerFactor));
}

#endif /* DIFFICULTY_H */
