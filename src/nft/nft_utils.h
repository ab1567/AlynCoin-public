#ifndef NFT_UTILS_H
#define NFT_UTILS_H

#include <string>
#include <cstdint>

std::string generateNFTID(const std::string& creator, const std::string& imageHash, int64_t timestamp);
std::string getLoadedWalletAddress();

#endif // NFT_UTILS_H
