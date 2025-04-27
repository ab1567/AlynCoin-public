#ifndef WINTERFELL_STARK_H
#define WINTERFELL_STARK_H

#include <string>
#include <ctime>
#include <vector>
#include <cstdint>
#include <iostream>
#include <optional>
#include "../nft/nft.h"

// ✅ Externally exposed hash function for Rust FFI
extern "C" void hash_blake3_256(const uint8_t* input, size_t len, uint8_t out[32]);

class WinterfellStark {
public:
    // ✅ Generate zk-STARK Proof for a block using blockHash + previousHash + txRoot
    static std::string generateProof(const std::string& blockHash,
                                     const std::string& prevHash,
                                     const std::string& txRoot);

    // ✅ Verify zk-STARK Proof for a block
    static bool verifyProof(const std::string& proof,
                            const std::string& blockHash,
                            const std::string& prevHash,
                            const std::string& txRoot);

    // ✅ Generate zk-STARK Proof for a transaction
    static std::string generateTransactionProof(const std::string& sender,
                                                const std::string& recipient,
                                                double amount,
                                                time_t timestamp);

    // ✅ Verify zk-STARK Proof for a transaction
    static bool verifyTransactionProof(const std::string& zkProof,
                                       const std::string& sender,
                                       const std::string& recipient,
                                       double amount,
                                       time_t timestamp);

    // ✅ Generate zk-STARK Proof for a zk-Identity
    static std::optional<std::string> generateIdentityProof(const std::string& uuid,
                                                            const std::string& name,
                                                            const std::string& metadataHash);

    // ✅ Generate Recursive zk-STARK Proof from inner proof + expected hash
    static std::string generateRecursiveProof(const std::string& address, size_t txCount);

    // ✅ NFT zk-STARK Proof Verification
    static bool verifyNFTZkProof(const NFT& nft) {
        if (nft.zkStarkProof.empty()) {
quietPrint( "❌ [NFT-ZK] Missing zk-STARK proof data.\n");
            return false;
        }
        const std::string proofStr(reinterpret_cast<const char*>(nft.zkStarkProof.data()), nft.zkStarkProof.size());
        const std::string dummyPrev = "";
        const std::string dummyRoot = "";
        return verifyProof(proofStr, nft.id, dummyPrev, dummyRoot);
    }

	static bool verifyIdentityProof(const std::string& proof, const std::string& uuid,
                                const std::string& name, const std::string& metadataHash);

};
class RollupStark {
public:
    static std::string generateRollupProof(const std::string& blockHash,
                                           const std::string& prevHash,
                                           const std::string& txRoot);

    static bool verifyRollupProof(const std::string& proof,
                                  const std::string& blockHash,
                                  const std::string& prevHash,
                                  const std::string& txRoot);
};
#endif // WINTERFELL_STARK_H
