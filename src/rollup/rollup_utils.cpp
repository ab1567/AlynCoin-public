#include "rollup_utils.h"
#include "crypto_utils.h"
#include <iostream>
#include <unordered_map>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <iomanip>
#include "db/db_paths.h"

// --- Merkle Root Calculation ---
std::string RollupUtils::calculateMerkleRoot(const std::vector<std::string>& leafHashes) {
    if (leafHashes.empty()) return "";
    std::vector<std::string> currentLevel = leafHashes;
    while (currentLevel.size() > 1) {
        std::vector<std::string> nextLevel;
        for (size_t i = 0; i < currentLevel.size(); i += 2) {
            std::string left = currentLevel[i];
            std::string right = (i + 1 < currentLevel.size()) ? currentLevel[i + 1] : left;
            std::string combined = "MerkleNode:" + left + right;
            nextLevel.push_back(Crypto::hybridHash(combined));
        }
        currentLevel = nextLevel;
    }
    return currentLevel.front();
}

// --- Hash Helpers ---
std::string RollupUtils::keccak256(const std::string& input) {
    return Crypto::keccak256(input);
}

std::string RollupUtils::hybridHashWithDomain(const std::string& input, const std::string& domain) {
    return Crypto::hybridHash(domain + ":" + input);
}

// --- Delta Compressor ---
std::vector<std::pair<std::string, double>> RollupUtils::compressStateDelta(
    const std::unordered_map<std::string, double>& before,
    const std::unordered_map<std::string, double>& after) {
    std::vector<std::pair<std::string, double>> delta;
    for (const auto& [addr, newBal] : after) {
        auto it = before.find(addr);
        double oldBal = (it != before.end()) ? it->second : 0.0;
        if (oldBal != newBal) {
            delta.emplace_back(addr, newBal - oldBal);
        }
    }
    return delta;
}

// --- Deterministic State Root ---
std::string RollupUtils::calculateStateRoot(const std::unordered_map<std::string, double>& state) {
    std::vector<std::string> accountHashes;
    accountHashes.reserve(state.size());
    for (const auto& [address, balance] : state) {
        std::ostringstream ss;
        ss << address;
        // Ensure consistent balance formatting (fixed, 8 decimals)
        ss << std::fixed << std::setprecision(8) << balance;
        std::string hash = hybridHashWithDomain(ss.str(), "StateTrace");
        accountHashes.push_back(hash);
    }
    std::sort(accountHashes.begin(), accountHashes.end());  // Deterministic ordering!
    return calculateMerkleRoot(accountHashes);
}

// --- Persistent Rollup Metadata ---
// If you have getHomePath() define it in db_paths.h/.cpp, or switch to getDataDir() for consistency.
static std::string getRollupMetaPath() {
    // Option A: (define getHomePath if missing)
    const char* home = std::getenv("HOME");
    std::string base = home ? std::string(home) : ".";
    return base + "/.alyncoin/rollup_meta.txt";

    // Option B: (if you have getDataDir)
    // return DBPaths::getDataDir() + "/rollup_meta.txt";
}

void RollupUtils::storeRollupMetadata(const std::string& txRoot, const std::string& blockHash) {
    std::ofstream file(getRollupMetaPath());
    if (file.is_open()) {
        file << txRoot << "\n" << blockHash;
        file.close();
    } else {
        std::cerr << "[ERROR] Could not open rollup_meta.txt for writing.\n";
    }
}

std::pair<std::string, std::string> RollupUtils::loadRollupMetadata() {
    std::ifstream file(getRollupMetaPath());
    std::string txRoot, blockHash;
    if (file.is_open()) {
        std::getline(file, txRoot);
        std::getline(file, blockHash);
        file.close();
    } else {
        std::cerr << "[ERROR] Could not open rollup_meta.txt for reading.\n";
    }
    return {txRoot, blockHash};
}
