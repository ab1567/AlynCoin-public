#include "difficulty.h"
#include <algorithm>
#include <cmath>
#include <mutex>
#include <unordered_map>
#include <boost/multiprecision/cpp_int.hpp>

using boost::multiprecision::cpp_int;

int getActiveMinerCount()
{
    std::lock_guard<std::timed_mutex> lk(peersMutex);
    return std::max(1, static_cast<int>(peerTransports.size()));
}

static std::unordered_map<int, cpp_int> workCache;

cpp_int difficultyToWork(int diff) {
    auto it = workCache.find(diff);
    if (it != workCache.end())
        return it->second;
    cpp_int w = (diff >= 0) ? (cpp_int(1) << diff) : cpp_int(1);
    workCache[diff] = w;
    return w;
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
