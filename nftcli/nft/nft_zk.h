#ifndef NFT_ZK_H
#define NFT_ZK_H

#include <string>
#include <vector>
#include <cstdint>

class NFT;  // Forward declaration of NFT class

class NFTZK {
public:
    static bool verifyProof(const std::vector<uint8_t>& proofData, const std::string& expectedHash);
    static bool generateProof(const std::string& input, std::vector<uint8_t>& outProof);
};

// ✅ External helper for verifying full zk-STARK proof from an NFT instance
bool verifyNFTZkProof(const NFT& nft);

#endif // NFT_ZK_H
