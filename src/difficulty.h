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
inline constexpr const char* AIRDROP_ADDRESS     = "a085b4150963341ba65798ad36bb2baff7acff97";
inline constexpr const char* LIQUIDITY_ADDRESS   = "6f8a94831f0a981e74dd3a276ec47936baa4fd39";
inline constexpr const char* INVESTOR_ADDRESS    = "5fb9ca2492f2bc88510b57860cdf74acf6bb4d94";
inline constexpr const char* DEVELOPMENT_ADDRESS = "20067d1e7ad17426f0aa23433e7cf33fde01376a";
inline constexpr const char* EXCHANGE_ADDRESS    = "e3cd089db202024ef48630db44f0ec2a832d0732";
inline constexpr const char* TEAM_FOUNDER_ADDRESS = "6b04101ffe25a34b993ae776421d1b93a173434c";

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
