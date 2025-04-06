#ifndef NFT_H
#define NFT_H

#include <string>
#include <vector>
#include <cstdint>
#include "generated/nft.pb.h"

class NFT {
public:
    // 🆔 Core NFT fields
    std::string id;
    std::string creator;
    std::string owner;
    std::string metadata;
    std::string imageHash;
    int64_t timestamp;
    std::vector<uint8_t> signature;

    // 🔐 zk-STARK proof
    std::vector<uint8_t> zkStarkProof;

    // 🧠 Optional fields
    std::string version;
    std::string nft_type;
    std::string proof_hash;
    std::string extra_data;

    NFT() = default;

    // 🔁 Serialization
    NFTProto toProto() const;
    bool fromProto(const NFTProto& proto);
    std::string toJSON() const;
    static NFT fromJSON(const std::string& jsonStr);

    // ✅ Verification
    bool verifySignature() const;
    bool verifyZkStarkProof() const;
};

#endif // NFT_H
