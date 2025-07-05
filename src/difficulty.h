#ifndef DIFFICULTY_H
#define DIFFICULTY_H

#include "blockchain.h"
#include <cstdint>
#include <boost/asio.hpp>
#include "transport/peer_globals.h"

// ===========================================================================
//  AlynCoin Monetary Base
//  --------------------------------------------------------------------------
//  • Premine: 10,000,000 ALYN minted in the genesis block (height = 0).
//    These coins are *already counted* in chain.getTotalSupply().
//  • Max supply: 100,000,000 ALYN
// ===========================================================================

constexpr uint64_t PREMINE_SUPPLY = 10'000'000;   // For clarity in docs/tests

// ─────────────────────────────────────────────────────────────────────────────
//  Helper: how many peers are actually submitting shares?
// ─────────────────────────────────────────────────────────────────────────────
int getActiveMinerCount();

// ─────────────────────────────────────────────────────────────────────────────
//  Difficulty ladder – user-friendly, piece-wise floor
//
//  Coins in circulation  |  Floor multiplier (× current diff)
//  ──────────────────────┼──────────────────────────────────
//    < 15 000 000  (includes 10 M premine) | 1.00   ← easy CPU tier
//    15 M – 19.9 M                         | 1.25
//    20 M – 29.9 M                         | 1.50
//    30 M – 49.9 M                         | 2.00
//    50 M – 79.9 M                         | 3.00
//    ≥ 80 M                                | 4.00   ← “serious-rig” era
// ─────────────────────────────────────────────────────────────────────────────
//
//  Retarget algorithm: LWMA-180 (≈3 hours worth of blocks) with
//  Digishield-style dampening so large hash-rate swings don’t shock the chain.
// ─────────────────────────────────────────────────────────────────────────────
uint64_t calculateSmartDifficulty(const Blockchain& chain);

#endif /* DIFFICULTY_H */
