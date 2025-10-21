
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
//   Logistic difficulty floor with soft tail
// ─────────────────────────────────────────────
static long double logisticFloor(long double s)
{
    constexpr long double base = 5.0L;
    constexpr long double logisticSpan = 35.0L;     // smooth growth up to midpoint
    constexpr long double k  = 6.0L / 100'000'000.0L;
    constexpr long double s0 = 50'000'000.0L;       // midpoint

    const long double logisticComponent =
        logisticSpan / (1.0L + std::exp(-k * (s - s0)));

    const long double tailBase =
        std::max<long double>(0.0L, (s - s0) / 5'000'000.0L);
    const long double tailComponent = std::log1p(tailBase);

    return base + logisticComponent + tailComponent;
}

// ─────────────────────────────────────────────
//   Core retarget – LWMA-based
// ─────────────────────────────────────────────
uint64_t calculateSmartDifficulty(const Blockchain& chain)
{
    /*  Design targets ———————————————————————
        • 120-second blocks
        • 720-block LWMA window  ≈ 24 h
        • Wider +100 % / −66 % bounds
        • Reduced Digishield dampening (40 % delta)
        • Small peer-count bonus, capped +15 %
    ------------------------------------------------*/
    constexpr int         LWMA_N      = 720;
    constexpr long double TARGET      = 120.0L;      // seconds / block
    constexpr long double MAX_UP      = 2.0L;        // at most +100 %
    constexpr long double MAX_DOWN    = 1.0L/3.0L;   // at most one-third
    constexpr long double DAMPING     = 0.40L;       // apply 40 % of delta
    constexpr uint64_t    GENESIS_DIFF   = 5;      // block #0 and #1
    constexpr size_t      LOCK_HEIGHT    = 2;      // genesis + first mined block

    const size_t height = chain.getBlockCount();
    if (height < 2)               // genesis or first mined block
        return GENESIS_DIFF;

    // ── Wall-clock sanity check (±60 min) ─────────────
    const auto& tip = chain.getLatestBlock();
    const std::time_t now = std::time(nullptr);
    if (tip.getTimestamp() > now + 3600 || tip.getTimestamp() < now - 3600)
        return tip.getDifficulty();

    // ── Fixed bootstrap: keep genesis and block #1 at diff-5 ────────
    if (height < LOCK_HEIGHT)
        return GENESIS_DIFF;

    // ── Difficulty floor considering recent hash rate ────────────
    const long double supply = static_cast<long double>(chain.getTotalSupply());
    const long double minFloor = logisticFloor(0.0L);
    const long double supplyFloor = logisticFloor(supply);
    const long double avgDiff = static_cast<long double>(chain.getAverageDifficulty(100));
    const long double hashFloor = std::max<long double>(minFloor, avgDiff * 0.4L);
    const long double floor  = std::max<long double>(supplyFloor, hashFloor);

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
    const long double rawBonus = std::min<long double>(1.15L,
                                             1.0L + 0.005L * getActiveMinerCount(chain));

    // Smooth miner-count swings so peers churning connections don't cause
    // block-to-block oscillations. Allow at most ±2 % change per block.
    static std::mutex bonusMutex;
    static long double previousBonus = 1.0L;
    constexpr long double MAX_BONUS_STEP = 0.02L;

    long double minerBonus = rawBonus;
    {
        std::lock_guard<std::mutex> guard(bonusMutex);

        if (minerBonus > previousBonus + MAX_BONUS_STEP)
            minerBonus = previousBonus + MAX_BONUS_STEP;
        else if (minerBonus < previousBonus - MAX_BONUS_STEP)
            minerBonus = previousBonus - MAX_BONUS_STEP;

        previousBonus = minerBonus;
    }

    // ── Apply ────────────────────────────────────────────────────
    long double nextRaw   = chain.getLatestBlock().difficulty * factor;


    const long double nextFloor = std::max<long double>(floor, nextRaw);

    long double nextDiff  = std::max<long double>(minFloor,
                                                 nextFloor * minerBonus);

    // ── Grace mode for severe hashrate collapse ───────────────
    static int slowCounter = 0;
    const auto& prevBlock = chain.getChain()[height - 2];
    if (tip.getTimestamp() - prevBlock.getTimestamp() > TARGET * 30)
        ++slowCounter;
    else
        slowCounter = std::max(0, slowCounter - 1);

    if (slowCounter > 30)
        nextDiff = std::max<long double>(minFloor,
                                         (nextFloor / 2.0L) * minerBonus);

    return static_cast<uint64_t>(std::llround(nextDiff));
}
