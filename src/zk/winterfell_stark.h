#ifndef WINTERFELL_STARK_H
#define WINTERFELL_STARK_H

#include <string>
#include <ctime>  // Required for time_t
#include <vector>
#include <cstdint>
#include <iostream>
#include "../nft/nft.h"

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

    static bool verifyNFTZkProof(const NFT& nft) {
    if (nft.zkStarkProof.empty()) {
        std::cerr << "❌ [NFT-ZK] Missing zk-STARK proof data.\n";
        return false;
    }
    const std::string proofStr(reinterpret_cast<const char*>(nft.zkStarkProof.data()), nft.zkStarkProof.size());
    const std::string dummyPrev = "";
    const std::string dummyRoot = "";
    return verifyProof(proofStr, nft.id, dummyPrev, dummyRoot);
}
};

#endif // WINTERFELL_STARK_H
