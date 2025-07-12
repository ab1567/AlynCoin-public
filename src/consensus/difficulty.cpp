#include "difficulty.h"
#include <algorithm>
#include <cmath>
#include <mutex>
#include <unordered_map>
#include <boost/multiprecision/cpp_int.hpp>

using boost::multiprecision::cpp_int;

// Global peer mutex and peer list should be declared elsewhere
extern std::timed_mutex peersMutex;
extern std::vector<int> peerTransports;

// Returns number of active mining peers (minimum 1)
int getActiveMinerCount() {
    std::lock_guard<std::timed_mutex> lk(peersMutex);
    return std::max(1, static_cast<int>(peerTransports.size()));
}

// Memoized conversion from integer difficulty to "work"
static std::unordered_map<int, cpp_int> workCache;
cpp_int difficultyToWork(int diff) {
    auto it = workCache.find(diff);
    if (it != workCache.end())
        return it->second;
    cpp_int w = (diff >= 0) ? (cpp_int(1) << diff) : cpp_int(1);
    workCache[diff] = w;
    return w;
}

// Calculates the adaptive network difficulty based on recent block times,
// total supply, and miner activity.
// - Uses LWMA-90 window (≈2¼ h at 90 s block target)
// - Floors are ramped up as more coins circulate
// - Block reward is handled elsewhere (default: 50 ALYN)
uint64_t calculateSmartDifficulty(const Blockchain& chain)
{
    constexpr int    LWMA_N     = 90;        // Window size (90 blocks)
    constexpr double TARGET     = 90.0;      // Target time per block (90 s)
    constexpr double MAX_UP     = 3.0;       // Maximum difficulty increase per window (×3)
    constexpr double MAX_DOWN   = 1.0/3.0;   // Maximum decrease per window (÷3)
    constexpr uint64_t GENESIS_DIFF = 1;

    size_t height = chain.getBlockCount();
    if (height < 2) return GENESIS_DIFF;

    // Get total supply in coins (double for smooth comparisons)
    double supply = static_cast<double>(chain.getTotalSupply());

    // Floor difficulty multiplier by supply zone (smooth ramp, *not* sharp jumps)
    double floorMult = 1.0;
    if      (supply >= 80'000'000) floorMult = 4.0;      // Ultra-high: ASIC/farm era
    else if (supply >= 60'000'000) floorMult = 3.0;      // Heavy: pro rigs only
    else if (supply >= 40'000'000) floorMult = 2.0;      // Hard: mid-pro GPU
    else if (supply >= 20'000'000) floorMult = 1.5;      // Moderate: high-end solo
    else if (supply >= 15'000'000) floorMult = 1.25;     // Easy/medium
    // Under 15M: "Lite" zone for CPUs/small GPU

    // --- LWMA difficulty calculation over last N blocks ---
    int  N = std::min<int>(LWMA_N, height - 1);
    long double sumW = 0.0, sumD = 0.0;

    for (int i = 1; i <= N; ++i) {
        const auto& cur  = chain.getChain()[height - i];
        const auto& prev = chain.getChain()[height - i - 1];
        long double solvetime = std::max<long double>(1,
                                 cur.getTimestamp() - prev.getTimestamp());
        sumW += i;
        sumD += i * solvetime;
    }

    long double lwma    = sumD / sumW;
    long double factor  = TARGET / lwma;
    factor = std::clamp(factor, MAX_DOWN, MAX_UP);

    // --- Gentle miner count bonus: +0.5% per miner, capped at +50% ---
    double minerFactor = std::min(1.5, 1.0 + 0.005 * getActiveMinerCount() * 100);

    // Previous block’s difficulty (should be stored in each block header)
    long double rawNext = chain.getLatestBlock().difficulty * factor;
    long double floored = std::max<long double>(floorMult, rawNext);

    // Minimum difficulty is 1 (can't go lower)
    return static_cast<uint64_t>(std::max<long double>(1.0, floored * minerFactor));
}
