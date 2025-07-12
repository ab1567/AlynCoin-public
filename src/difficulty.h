#ifndef DIFFICULTY_H
#define DIFFICULTY_H

#include "blockchain.h"
#include <cstdint>
#include <boost/multiprecision/cpp_int.hpp>
#include "transport/peer_globals.h"

// ────────────────────────────────────────────────────────────────
//  AlynCoin Monetary Base
// ────────────────────────────────────────────────────────────────
//  • Premine: 10 000 000 ALYN (height 0) – already counted by
//    chain.getTotalSupply().
//  • Max supply: 100 000 000 ALYN
// ────────────────────────────────────────────────────────────────
constexpr uint64_t PREMINE_SUPPLY = 10'000'000;   // for clarity in docs/tests

// ────────────────────────────────────────────────────────────────
//  Helpers
// ────────────────────────────────────────────────────────────────
int  getActiveMinerCount();                 // how many peers are mining?
boost::multiprecision::cpp_int difficultyToWork(int diff);

// ────────────────────────────────────────────────────────────────
//  Difficulty ladder  (floor-multiplier × current diff)
//
//  Circulating supply     Floor
//  ─────────────────────  ───────────────────────────────────────
//     < 15 000 000        1.0   (very easy / CPU era)
//     15 – 19.9 M         1.25
//     20 – 29.9 M         1.50
//     30 – 39.9 M         1.75
//     40 – 49.9 M         2.00
//     50 – 69.9 M         2.50
//     70 – 89.9 M         3.00
//     ≥ 90 000 000        4.00  (ASIC/farm)
//
//  Retarget algorithm: LWMA-120 (≈3 h @ 90 s target) + Digishield
//  dampening.  One-block retarget – no epoch waiting.
// ────────────────────────────────────────────────────────────────
uint64_t calculateSmartDifficulty(const Blockchain& chain);

#endif /* DIFFICULTY_H */
