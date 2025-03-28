#ifndef ROLLUP_UTILS_H
#define ROLLUP_UTILS_H

#include <string>
#include <vector>
#include <unordered_map>

class RollupUtils {
public:
    static std::string calculateMerkleRoot(const std::vector<std::string>& txHashes);
    static std::string keccak256(const std::string& input);
    static std::string hybridHashWithDomain(const std::string& input, const std::string& domain);

    // ✅ New: Compress state delta (non-zero changes only)
    static std::vector<std::pair<std::string, double>> compressStateDelta(const std::unordered_map<std::string, double>& before,
                                                                         const std::unordered_map<std::string, double>& after);
};

#endif // ROLLUP_UTILS_H
