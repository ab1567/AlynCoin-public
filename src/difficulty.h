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
inline constexpr const char* AIRDROP_ADDRESS     = "ae87f81b5f039b9714f3e3b9fbe89cd871f49d7e";
inline constexpr const char* LIQUIDITY_ADDRESS   = "39d849e2bc8aee655e72ee45c798f2a28ff75d59";
inline constexpr const char* INVESTOR_ADDRESS    = "a04fc0ff008c03a22c6d34a5c231a185f09cf65a";
inline constexpr const char* DEVELOPMENT_ADDRESS = "60227c9836de4d5f94ce812464082507d8304d3f";
inline constexpr const char* EXCHANGE_ADDRESS    = "256ab743e22e11b42654d5e4bb355d858797005c";
inline constexpr const char* TEAM_FOUNDER_ADDRESS = "ae5809b3ec42c4021bcc4846e556b8353922de97";

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
