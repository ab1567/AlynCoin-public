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
    constexpr int    WINDOW       = 30;      // blocks
    constexpr double TARGET_SEC   = 60.0;    // seconds / block
    constexpr uint64_t GENESIS_DIFF = 1;

    const size_t height = chain.getBlockCount();
    if (height < 2) return GENESIS_DIFF;

    if (height <= WINDOW)
        return chain.getLatestBlock().difficulty;

    const Block& lastBlock   = chain.getLatestBlock();
    const Block& windowStart = chain.getChain()[height - WINDOW - 1];

    double actual   = std::difftime(lastBlock.getTimestamp(), windowStart.getTimestamp());
    double expected = WINDOW * TARGET_SEC;
    double ratio    = actual / expected;
    ratio = std::clamp(ratio, 0.25, 4.0);

    double newTarget = chain.getLatestBlock().difficulty * ratio;
    return static_cast<uint64_t>(std::max<double>(1.0, newTarget));
}
