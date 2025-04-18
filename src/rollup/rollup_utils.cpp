#include "rollup_utils.h"
#include "crypto_utils.h"
#include <iostream>
#include <unordered_map>
#include <sstream>
#include <fstream>  // ✅ Required for ifstream/ofstream

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

std::string RollupUtils::keccak256(const std::string& input) {
    return Crypto::keccak256(input);
}

std::string RollupUtils::hybridHashWithDomain(const std::string& input, const std::string& domain) {
    return Crypto::hybridHash(domain + ":" + input);
}

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

std::string RollupUtils::calculateStateRoot(const std::unordered_map<std::string, double>& state) {
    std::vector<std::string> accountHashes;
    for (const auto& [address, balance] : state) {
        std::ostringstream ss;
        ss << address << balance;
        std::string hash = hybridHashWithDomain(ss.str(), "StateTrace");
        accountHashes.push_back(hash);
    }
    return calculateMerkleRoot(accountHashes);
}

void RollupUtils::storeRollupMetadata(const std::string& txRoot, const std::string& blockHash) {
    std::ofstream file("/root/.alyncoin/rollup_meta.txt");
    if (file.is_open()) {
        file << txRoot << "\n" << blockHash;
        file.close();
    } else {
        std::cerr << "[ERROR] Could not open rollup_meta.txt for writing.\n";
    }
}

std::pair<std::string, std::string> RollupUtils::loadRollupMetadata() {
    std::ifstream file("/root/.alyncoin/rollup_meta.txt");
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
