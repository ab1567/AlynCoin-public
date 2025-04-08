#ifndef ZK_IDENTITY_H
#define ZK_IDENTITY_H

#include <string>
#include <optional>
#include <ctime>

struct ZkIdentity {
    std::string uuid;
    std::string name;
    std::string publicKey;
    std::string metadataHash;
    std::optional<std::string> zkProof;
    std::optional<std::string> falconSignature;
    std::optional<std::string> dilithiumSignature;
    time_t createdAt;

    std::string toString() const;
    bool sign(const std::string& signerAddress);
    bool generateZkProof();
};

#endif // ZK_IDENTITY_H
