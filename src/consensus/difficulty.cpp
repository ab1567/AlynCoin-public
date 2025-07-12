
#include "difficulty.h"
#include <algorithm>
#include <cmath>
#include <mutex>
#include <unordered_map>
#include <boost/multiprecision/cpp_int.hpp>
#include "transport/peer_globals.h"

using boost::multiprecision::cpp_int;

// ─────────────────────────────────────────────
//   Active-miner heuristic (greatly toned down)
// ─────────────────────────────────────────────
int getActiveMinerCount()
{
    std::lock_guard<std::timed_mutex> g(peersMutex);
    return std::max(1, static_cast<int>(peerTransports.size()));
}

// ─────────────────────────────────────────────
//   Memoised 2^diff → work
// ─────────────────────────────────────────────
static std::unordered_map<int, cpp_int> workCache;

cpp_int difficultyToWork(int diff)
{
    if (auto it = workCache.find(diff); it != workCache.end())
        return it->second;

    cpp_int w = (diff >= 0) ? (cpp_int(1) << diff) : cpp_int(1);
    workCache.emplace(diff, w);
    return w;
}

// ─────────────────────────────────────────────
//   Core retarget – LWMA-based
// ─────────────────────────────────────────────
uint64_t calculateSmartDifficulty(const Blockchain& chain)
{
    /*  Design targets ———————————————————————
        • 120-second blocks
        • 360-block LWMA window  ≈ 12 h
        • Very soft ± limits (×2 / ÷ 3)
        • Extra Digishield dampening 0.5
        • Small peer-count bonus, capped +15 %
    ------------------------------------------------*/
    constexpr int         LWMA_N      = 360;
    constexpr long double TARGET      = 120.0L;      // seconds / block
    constexpr long double MAX_UP      = 2.0L;        // at most double
    constexpr long double MAX_DOWN    = 1.0L/3.0L;   // at most one-third
    constexpr long double DAMPING     = 0.50L;       // apply 50 % of delta
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

    // ── LWMA-360 with linear weights ──────────────
    const int N = std::min<int>(LWMA_N, height - 1);
    long double sumW = 0.0L, sumST = 0.0L;

    for (int i = 1; i <= N; ++i) {
        const auto& cur  = chain.getChain()[height - i];
        const auto& prev = chain.getChain()[height - i - 1];

        const long double st = static_cast<long double>(
            std::clamp<int64_t>(cur.getTimestamp() - prev.getTimestamp(),
                                1, static_cast<int64_t>(6 * TARGET))); // tighter clamp

        const long double w  = i;              // linear weight
        sumW  += w;
        sumST += w * st;
    }

    long double lwma   = sumST / sumW;
    long double factor = TARGET / lwma;        // >1 if we're too fast
    factor             = std::clamp(factor, MAX_DOWN, MAX_UP);
    factor             = 1.0L + (factor - 1.0L) * DAMPING;

    // ── Peer-count bonus (much weaker) ────────────
    const double minerBonus = std::min(1.15,          // +15 % cap
                              1.0 + 0.001 * getActiveMinerCount());

    // ── Apply ────────────────────────────────────────────────────
    const long double nextRaw   = chain.getLatestBlock().difficulty * factor;
    const long double nextFloor = std::max<long double>(floorMult, nextRaw);

    const long double nextDiff  = std::max<long double>(1.0,
                                nextFloor * minerBonus);

    return static_cast<uint64_t>(std::llround(nextDiff));
}
