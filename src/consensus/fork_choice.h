#pragma once
#include "block.h"

inline bool isBetterTip(const Block& a, const Block& b) noexcept {
    if (a.getAccumulatedWork() > b.getAccumulatedWork()) return true;
    if (a.getAccumulatedWork() < b.getAccumulatedWork()) return false;
    return a.getHash() < b.getHash();
}
