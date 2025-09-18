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
inline constexpr const char* AIRDROP_ADDRESS     = "9a3d60db8c4aa4e56d4af1e2ca08add8613ad10f";
inline constexpr const char* LIQUIDITY_ADDRESS   = "48cb2ae09f550de06f0caff91fb9690e95c9bbc3";
inline constexpr const char* INVESTOR_ADDRESS    = "806cc16a6f7235f09bc753923c2c15b721c8f442";
inline constexpr const char* DEVELOPMENT_ADDRESS = "406317234be65bf7cc6e8e117b3404a4260f657d";
inline constexpr const char* EXCHANGE_ADDRESS    = "0267d5c4d63c4223a9ae9ac8ada00dd75357be31";
inline constexpr const char* TEAM_FOUNDER_ADDRESS = "d823146d399e22d35739c78cef0ad8ff664311f5";

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
