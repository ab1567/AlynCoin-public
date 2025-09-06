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
inline constexpr const char* AIRDROP_ADDRESS     = "4917e92b2dba79df9a794ff2be5c88da6d3fdd91";
inline constexpr const char* LIQUIDITY_ADDRESS   = "b383cbbf840266cf7594d3985320dffae1a077bc";
inline constexpr const char* INVESTOR_ADDRESS    = "c209eee640aa2386c27ae9fbe111f8c498f4973c";
inline constexpr const char* DEVELOPMENT_ADDRESS = "23916872580a6dd4a088dd718cbb20b61ec2d56e";
inline constexpr const char* EXCHANGE_ADDRESS    = "c2ab555dbc5aa2ed188aaf630b95b3cfa97239af";
inline constexpr const char* TEAM_FOUNDER_ADDRESS = "f01522a535f4e22319fa78c6532d4e081d41c6b6";

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
