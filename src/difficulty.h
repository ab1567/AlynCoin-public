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
inline constexpr const char* AIRDROP_ADDRESS     = "aad1232fd2b7e523881a47777d04527fac46810d";
inline constexpr const char* LIQUIDITY_ADDRESS   = "50582e6f0138f60885e551b334dbdc310f203673";
inline constexpr const char* INVESTOR_ADDRESS    = "7c88f8663418d4b17d25828ad717b853d5ff5c5e";
inline constexpr const char* DEVELOPMENT_ADDRESS = "f3d6f1516eea34434533cbd0a63ef9fb905c2b33";
inline constexpr const char* EXCHANGE_ADDRESS    = "43899bf7799dd3003f8af338ae34c8ed18652823";
inline constexpr const char* TEAM_FOUNDER_ADDRESS = "9ad8c6b6a9dbe1808f781f89962f95de65aef35c";

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
