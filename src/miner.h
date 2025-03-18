#ifndef MINER_H
#define MINER_H

#include <atomic>
#include <string>
#include "blockchain.h"

extern std::atomic<bool> miningActive;

class Miner {
public:
    static std::string mineBlock(int difficulty);  // ✅ FIXED: Add inside class
    static void startMiningProcess(const std::string& minerAddress);
};

#endif // MINER_H
