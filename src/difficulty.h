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

// Premine recipient addresses
inline constexpr const char* AIRDROP_ADDRESS     = "b23852aaeda989786fbd1502b6bf322ac034aea8";
inline constexpr const char* LIQUIDITY_ADDRESS   = "458d57f5a7086d73cbe31129302df818b55a3266";
inline constexpr const char* INVESTOR_ADDRESS    = "ab704d12a9d80aef036bc22f86823421f555704d";
inline constexpr const char* DEVELOPMENT_ADDRESS = "10b551b5557a00ba5d47a87b09409b42c6213759";
inline constexpr const char* EXCHANGE_ADDRESS    = "9bb9b458a2c3fb38242966d499f122836c31b4e0";
inline constexpr const char* TEAM_FOUNDER_ADDRESS = "36b385a9da7243d0c96ce507fe825b4c3206d175";

// ────────────────────────────────────────────────────────────────
//  Helpers
// ────────────────────────────────────────────────────────────────
int  getActiveMinerCount(const Blockchain& chain);  // unique miners in last window
boost::multiprecision::cpp_int difficultyToWork(int diff);

// ────────────────────────────────────────────────────────────────
//  Difficulty floor (logistic)
//  rises smoothly from 5 → 40 as supply → 100 M.
//
//  Retarget algorithm: LWMA-720 (≈24 h @ 120 s target)
//  with stronger dampening and mild miner-count bonus. One-block
//  retarget – no epoch waiting.
// ────────────────────────────────────────────────────────────────
uint64_t calculateSmartDifficulty(const Blockchain& chain);

#endif /* DIFFICULTY_H */
