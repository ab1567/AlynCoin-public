#include "nft_utils.h"
#include <fstream>
#include <algorithm>
#include <random>
#include <chrono>
#include "db/db_paths.h"
#include "crypto_utils.h"  // or wherever your Crypto::sha256 is

std::string generateNFTID(const std::string& creator, const std::string& imageHash, int64_t timestamp) {
    std::string salt = Crypto::sha256(std::to_string(rand()));
    return Crypto::sha256(creator + imageHash + std::to_string(timestamp) + salt);
}

std::string getLoadedWalletAddress() {
    const std::string walletFile = DBPaths::getHomePath() + "/.alyncoin/current_wallet.txt";
    std::ifstream file(walletFile);
    std::string address;
    if (file.is_open()) {
        std::getline(file, address);
        file.close();
    }
    address.erase(std::remove_if(address.begin(), address.end(),
        [](unsigned char c) { return std::isspace(c) || !std::isprint(c); }), address.end());

    if (address.empty() || address.length() != 40 ||
        address.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos) {
        return "";
    }
    return address;
}
