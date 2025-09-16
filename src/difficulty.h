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
inline constexpr const char* AIRDROP_ADDRESS     = "807b626b20d5a0e44841ee028da4d20e26e016cd";
inline constexpr const char* LIQUIDITY_ADDRESS   = "1adf369edf61ceb892d275d32941d48f96f6bfb5";
inline constexpr const char* INVESTOR_ADDRESS    = "6d1b1dafc7fc47d5263d9fcd3884e8d5005062ad";
inline constexpr const char* DEVELOPMENT_ADDRESS = "d42b813da130f1a03aad47f5da170a150a40b55f";
inline constexpr const char* EXCHANGE_ADDRESS    = "b24d84c9b750438fbfb1f618cf2da87b000ffcbe";
inline constexpr const char* TEAM_FOUNDER_ADDRESS = "24741a5230a32300aebe0bae7439f3e167776571";

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
