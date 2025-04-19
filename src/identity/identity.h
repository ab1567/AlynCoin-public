#ifndef ZK_IDENTITY_H
#define ZK_IDENTITY_H

#include <string>
#include <optional>
#include <ctime>
#include <vector>

struct ZkIdentity {
    std::string uuid;
    std::string name;
    std::string publicKey;
    std::string metadataHash;

    std::optional<std::vector<unsigned char>> zkProof;
    std::optional<std::vector<unsigned char>> falconSignature;
    std::optional<std::vector<unsigned char>> dilithiumSignature;

    time_t createdAt;

    std::string toString() const;
    bool sign(const std::string& signerAddress);
    bool generateZkProof();
    bool verifySignature() const;
};

#endif // ZK_IDENTITY_H
