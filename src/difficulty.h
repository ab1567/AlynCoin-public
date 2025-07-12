#ifndef DIFFICULTY_H
#define DIFFICULTY_H

#include "blockchain.h"
#include <cstdint>
#include <boost/multiprecision/cpp_int.hpp>

// ===========================================================================
//  AlynCoin Monetary Base
//  --------------------------------------------------------------------------
//  • Premine: 10,000,000 ALYN in genesis block (height = 0)
//  • Max supply: 100,000,000 ALYN (final cap)
// ===========================================================================

constexpr uint64_t PREMINE_SUPPLY = 10'000'000;

// Helper: Returns the current active miner count (minimum 1)
int getActiveMinerCount();

// Converts a difficulty integer to a corresponding "work" value
boost::multiprecision::cpp_int difficultyToWork(int diff);

// Difficulty retarget using a smoothed, multi-zone floor and fast-recovery LWMA
uint64_t calculateSmartDifficulty(const Blockchain& chain);

#endif /* DIFFICULTY_H */
