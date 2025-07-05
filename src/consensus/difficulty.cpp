#include "difficulty.h"
#include <algorithm>
#include <cmath>
#include <mutex>

int getActiveMinerCount()
{
    std::lock_guard<std::timed_mutex> lk(peersMutex);
    return std::max(1, static_cast<int>(peerTransports.size()));
}

uint64_t calculateSmartDifficulty(const Blockchain& chain)
{
    constexpr int    LWMA_N     = 180;      // sample window (blocks)
    constexpr double TARGET     = 60.0;     // seconds / block
    constexpr double MAX_UP     = 1.8;      // +80 % / window
    constexpr double MAX_DOWN   = 0.6;      // –40 % / window
    constexpr uint64_t GENESIS_DIFF = 1;

    const size_t height = chain.getBlockCount();
    if (height < 2) return GENESIS_DIFF;

    const double supply = static_cast<double>(chain.getTotalSupply());
    double floorMult = 1.0;
    if      (supply >= 80'000'000) floorMult = 4.0;
    else if (supply >= 50'000'000) floorMult = 3.0;
    else if (supply >= 30'000'000) floorMult = 2.0;
    else if (supply >= 20'000'000) floorMult = 1.50;
    else if (supply >= 15'000'000) floorMult = 1.25;

    const int  N = std::min<int>(LWMA_N, height - 1);
    long double sumW = 0.0, sumD = 0.0;

    for (int i = 1; i <= N; ++i)
    {
        const auto& cur  = chain.getChain()[height - i];
        const auto& prev = chain.getChain()[height - i - 1];

        long double solvetime = std::max<long double>(1,
                             cur.getTimestamp() - prev.getTimestamp());

        sumW += i;
        sumD += i * solvetime;
    }

    const long double lwma    = sumD / sumW;
    long double factor        = TARGET / lwma;
    factor = std::clamp(factor,
                        static_cast<long double>(MAX_DOWN),
                        static_cast<long double>(MAX_UP));

    const double minerFactor  = std::min(2.0,
                               1.0 + getActiveMinerCount() / 200.0);

    const long double rawNext = chain.getLatestBlock().difficulty * factor;
    const long double floored = std::max<long double>(floorMult, rawNext);

    return static_cast<uint64_t>(std::max<long double>(1.0,
                                floored * minerFactor));
}
