
#include "difficulty.h"
#include <algorithm>
#include <cmath>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <ctime>
#include <boost/multiprecision/cpp_int.hpp>
#include "transport/peer_globals.h"

using boost::multiprecision::cpp_int;

// ─────────────────────────────────────────────
//   Active-miner heuristic (greatly toned down)
// ─────────────────────────────────────────────
int getActiveMinerCount(const Blockchain& chain)
{
    const int window = 100; // last 100 blocks
    const auto& ch   = chain.getChain();
    const int start  = std::max(0, static_cast<int>(ch.size()) - window);

    std::unordered_set<std::string> miners;
    for (int i = start; i < static_cast<int>(ch.size()); ++i) {
        const std::string& addr = ch[i].getMinerAddress();
        if (!addr.empty())
            miners.insert(addr);
    }

    return std::max(1, static_cast<int>(miners.size()));
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
//   Logistic difficulty floor 5 → 40
// ─────────────────────────────────────────────
static long double logisticFloor(long double s)
{
    constexpr long double base = 5.0L;
    constexpr long double maxExtra = 35.0L;     // tops at 40
    constexpr long double k  = 6.0L / 100'000'000.0L;
    constexpr long double s0 = 50'000'000.0L;   // midpoint
    return base + maxExtra / (1.0L + std::exp(-k * (s - s0)));
}

// ─────────────────────────────────────────────
//   Core retarget – LWMA-based
// ─────────────────────────────────────────────
uint64_t calculateSmartDifficulty(const Blockchain& chain)
{
    /*  Design targets ———————————————————————
        • 120-second blocks
        • 720-block LWMA window  ≈ 24 h
        • Very soft ± limits (×3 / ÷ 3)
        • Extra Digishield dampening 0.5
        • Small peer-count bonus, capped +15 %
    ------------------------------------------------*/
    constexpr int         LWMA_N      = 720;
    constexpr long double TARGET      = 120.0L;      // seconds / block
    constexpr long double MAX_UP      = 3.0L;        // at most triple
    constexpr long double MAX_DOWN    = 1.0L/3.0L;   // at most one-third
    constexpr long double DAMPING     = 0.50L;       // apply 50 % of delta
    constexpr uint64_t    GENESIS_DIFF   = 5;      // block #0 and #1
    constexpr long double ABSOLUTE_FLOOR = 5.0L;   // hard floor
    constexpr size_t      LOCK_HEIGHT    = 60;     // first 60 blocks locked

    const size_t height = chain.getBlockCount();
    if (height < 2)               // genesis or first mined block
        return GENESIS_DIFF;

    // ── Wall-clock sanity check (±60 min) ─────────────
    const auto& tip = chain.getLatestBlock();
    const std::time_t now = std::time(nullptr);
    if (tip.getTimestamp() > now + 3600 || tip.getTimestamp() < now - 3600)
        return tip.getDifficulty();

    // ── Fixed bootstrap: keep first 60 blocks at diff-5 ────────
    if (height < LOCK_HEIGHT)
        return GENESIS_DIFF;

    // ── Difficulty floor considering recent hash rate ────────────
    const long double supply = static_cast<long double>(chain.getTotalSupply());
    const long double supplyFloor = logisticFloor(supply);
    const long double avgDiff = static_cast<long double>(chain.getAverageDifficulty(100));
    const long double hashFloor = std::max<long double>(ABSOLUTE_FLOOR, avgDiff * 0.5L);
    const long double floor  = std::min<long double>(supplyFloor, hashFloor);

    // ── LWMA-720 with harmonic weighting ──────────
    const int N = std::min<int>(LWMA_N, height - 1);
    long double sumW = 0.0L, denom = 0.0L;

    for (int i = 1; i <= N; ++i) {
        const auto& cur  = chain.getChain()[height - i];
        const auto& prev = chain.getChain()[height - i - 1];

        const long double mtpPrev = static_cast<long double>(chain.medianTimePast(height - i - 1));

        long double curTS = static_cast<long double>(cur.getTimestamp());
        curTS = std::clamp<long double>(curTS, mtpPrev - 7200.0L, mtpPrev + 7200.0L);

        const long double st = std::clamp<long double>(
            curTS - mtpPrev,
            TARGET / 4.0L,
            6 * TARGET);

        const long double w  = i;              // linear weight
        sumW  += w;
        denom += w / st;       // harmonic contribution
    }

    long double lwma   = sumW / denom;     // harmonic mean
    long double factor = TARGET / lwma;        // >1 if we're too fast
    factor             = std::clamp(factor, MAX_DOWN, MAX_UP);
    factor             = 1.0L + (factor - 1.0L) * DAMPING;

    // ── Peer-count bonus (much weaker) ────────────
    const double minerBonus = std::min(1.15,          // +15 % cap
                              1.0 + 0.001 * getActiveMinerCount(chain));

    // ── Apply ────────────────────────────────────────────────────
    long double nextRaw   = chain.getLatestBlock().difficulty * factor;


    const long double nextFloor = std::max<long double>(floor, nextRaw);

    long double nextDiff  =
        std::max<long double>(ABSOLUTE_FLOOR, nextFloor * minerBonus);

    // ── Grace mode for severe hashrate collapse ───────────────
    static int slowCounter = 0;
    const auto& prevBlock = chain.getChain()[height - 2];
    if (tip.getTimestamp() - prevBlock.getTimestamp() > TARGET * 30)
        ++slowCounter;
    else
        slowCounter = std::max(0, slowCounter - 1);

    if (slowCounter > 30)
        nextDiff = std::max<long double>(ABSOLUTE_FLOOR,
                                         (nextFloor / 2.0L) * minerBonus);

    return static_cast<uint64_t>(std::llround(nextDiff));
}
