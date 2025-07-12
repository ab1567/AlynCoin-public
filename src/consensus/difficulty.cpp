
#include "difficulty.h"
#include <algorithm>
#include <cmath>
#include <mutex>
#include <unordered_map>
#include <boost/multiprecision/cpp_int.hpp>
#include "transport/peer_globals.h"

using boost::multiprecision::cpp_int;

// ────────────────────────────────────────────────────────────────
//  Active-miner heuristic
// ────────────────────────────────────────────────────────────────
int getActiveMinerCount()
{
    std::lock_guard<std::timed_mutex> g(peersMutex);
    return std::max(1, static_cast<int>(peerTransports.size()));
}

// ────────────────────────────────────────────────────────────────
//  Cached 2 ^ diff  →  “work”
// ────────────────────────────────────────────────────────────────
static std::unordered_map<int, cpp_int> workCache;

cpp_int difficultyToWork(int diff)
{
    if (auto it = workCache.find(diff); it != workCache.end())
        return it->second;

    cpp_int w = (diff >= 0) ? (cpp_int(1) << diff) : cpp_int(1);
    workCache.emplace(diff, w);
    return w;
}

// ────────────────────────────────────────────────────────────────
//  Core retarget
// ────────────────────────────────────────────────────────────────
uint64_t calculateSmartDifficulty(const Blockchain& chain)
{
    constexpr int         LWMA_N      = 120;          // 120-block window
    constexpr long double TARGET      = 90.0L;        // 90 s / block
    constexpr long double MAX_UP      = 4.0L;         // max ×4 per window
    constexpr long double MAX_DOWN    = 0.5L;         // max ÷2 per window
    constexpr long double DAMPING     = 0.33L;        // Digishield (⅓)
    constexpr uint64_t    GENESIS_DIFF = 1;

    const size_t height = chain.getBlockCount();
    if (height < 2) return GENESIS_DIFF;

    // ── Difficulty floor by circulating supply ───────────────────
    const double supply = static_cast<double>(chain.getTotalSupply());
    long double floorMult = 1.0;

    if      (supply >= 90'000'000) floorMult = 4.0;
    else if (supply >= 70'000'000) floorMult = 3.0;
    else if (supply >= 50'000'000) floorMult = 2.5;
    else if (supply >= 40'000'000) floorMult = 2.0;
    else if (supply >= 30'000'000) floorMult = 1.75;
    else if (supply >= 20'000'000) floorMult = 1.5;
    else if (supply >= 15'000'000) floorMult = 1.25;

    // ── LWMA-120 (weighted) ──────────────────────────────────────
    const int  N = std::min<int>(LWMA_N, height - 1);
    long double sumW = 0.0L, sumST = 0.0L;

    for (int i = 1; i <= N; ++i) {
        const auto& cur  = chain.getChain()[height - i];
        const auto& prev = chain.getChain()[height - i - 1];

        long double st = static_cast<long double>(
            std::clamp<int64_t>(cur.getTimestamp() - prev.getTimestamp(),
                                1, 10 * TARGET));      // anti-timestamp-spam

        const long double w = i;                       // linear weight
        sumW  += w;
        sumST += w * st;
    }

    const long double lwma = sumST / sumW;
    long double factor     = TARGET / lwma;            // >1  → speed-up
    factor                  = std::clamp(factor, MAX_DOWN, MAX_UP);

    // Digishield dampening (makes jumps smoother but still responsive)
    factor = 1.0L + (factor - 1.0L) * DAMPING;

    // ── Small bonus for extra miners (prevents gaming by a single whale) ──
    const double minerBonus = std::min(1.30,               // cap +30 %
                               1.0 + 0.003 * getActiveMinerCount());

    // ── Apply ────────────────────────────────────────────────────
    const long double nextRaw   = chain.getLatestBlock().difficulty * factor;
    const long double nextFloor = std::max<long double>(floorMult, nextRaw);

    const long double nextDiff  = std::max<long double>(1.0,
                                nextFloor * minerBonus);

    return static_cast<uint64_t>(std::llround(nextDiff));
}
