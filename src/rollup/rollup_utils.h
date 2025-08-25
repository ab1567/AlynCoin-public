#ifndef ROLLUP_UTILS_H
#define ROLLUP_UTILS_H

#include <string>
#include <vector>
#include <unordered_map>
#include "../layer2/l2_executor.h"

class RollupUtils {
public:
    // 🌳 Merkle Root Calculation (for transaction or state traces)
    static std::string calculateMerkleRoot(const std::vector<std::string>& leafHashes);

    // 🔐 Crypto Hash Helpers
    static std::string keccak256(const std::string& input);
    static std::string hybridHashWithDomain(const std::string& input, const std::string& domain);

    // 📦 State Delta Compressor (only changed balances)
    static std::vector<std::pair<std::string, double>> compressStateDelta(
        const std::unordered_map<std::string, double>& before,
        const std::unordered_map<std::string, double>& after);

    // 🌐 Deterministic state root for rollups
    static std::string calculateStateRoot(const std::unordered_map<std::string, double>& state);

    // 🧾 Commitment over L2 execution receipts
    static std::string commitReceipts(const std::vector<L2Receipt>& receipts);

    // ✅ Persistent metadata helpers
    static void storeRollupMetadata(const std::string& txRoot, const std::string& blockHash);
    static std::pair<std::string, std::string> loadRollupMetadata();
};

#endif // ROLLUP_UTILS_H
