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
    std::vector<std::string> previous_versions;
    // 👤 Creator identity (e.g., name, alias)
    std::string creator_identity;

    // 📦 Bundled assets (e.g., image filenames, asset IDs)
    std::vector<std::string> bundledAssets;

    // 📜 Transfer ledger
    std::vector<std::string> transferHistory;

    // 🔐 Dual-signature (Dilithium)
    std::vector<uint8_t> dilithium_signature;

    // ⏳ Expiry and Revocation
    int64_t expiry_timestamp = 0;
    bool revoked = false;

    // 🔒 Encrypted metadata (optional)
    std::string encrypted_metadata;

    NFT() = default;

    // 🔁 Serialization
    NFTProto toProto() const;
    bool fromProto(const NFTProto& proto);
    std::string toJSON() const;
    static NFT fromJSON(const std::string& jsonStr);

    // ✅ Verification
    bool verifySignature() const;
    bool verifyZkStarkProof() const;

    // ⚙️ Proof generation
    void generateZkStarkProof();

    // 📤 Metadata submission
    bool submitMetadataHashTransaction() const;

    // 📦 Export
    bool exportToFile(const std::string& filename = "") const;

   std::string getSignatureMessage() const {
    return id + creator + owner + metadata + imageHash + std::to_string(timestamp);
  }

};

// === Standalone utility declarations for reMint ===
std::string calculateHash(const std::string& input);
std::string generateZkStarkProof(const std::string& metadata, const std::string& imageHash, const std::string& creator);
bool submitMetadataHashTransaction(const std::string& metadataHash, const std::string& creator,
                                   const std::string& signatureScheme, bool isReMint);
void exportNFTtoFile(const std::string& filename, const std::string& metadataHash,
                     const std::string& creator, const std::string& version,
                     const std::string& zkProof);
bool reMintNFT(const std::string& creator,
               const std::string& prevNftId,
               const std::string& newMetadata,
               const std::string& imageHash,
               const std::string& signatureScheme,
               const std::string& previousVersion,
               const std::string& previousZkProof);

#endif // NFT_H
