#include "hash.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <sstream>
#include <iomanip>
#include <iostream>

// ✅ Compute SHA-256 Hash
std::string sha256(const std::string &input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned int hashLength = 0;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();

    if (!mdctx) {
        std::cerr << "❌ Error: Failed to create EVP_MD_CTX!" << std::endl;
        return "";
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(mdctx, input.c_str(), input.size()) != 1 ||
        EVP_DigestFinal_ex(mdctx, hash, &hashLength) != 1) {  // ✅ Store hash length
        std::cerr << "❌ Error: SHA-256 hashing failed!" << std::endl;
        EVP_MD_CTX_free(mdctx);
        return "";
    }

    EVP_MD_CTX_free(mdctx);

    // ✅ Convert hash bytes to hex string
    std::ostringstream ss;
    ss << std::hex << std::setw(2) << std::setfill('0');

    for (size_t i = 0; i < hashLength; i++) {  // ✅ Use `hashLength` instead of fixed size
        ss << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }

    return ss.str();
}
