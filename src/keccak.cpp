#include "keccak.h"
#include <openssl/evp.h>
#include <sstream>
#include <iomanip>

std::vector<uint8_t> Keccak::keccak256_raw(const std::vector<uint8_t>& input) {
    std::vector<uint8_t> hash(EVP_MAX_MD_SIZE);
    unsigned int length = 0;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha3_256(), nullptr);
    EVP_DigestUpdate(ctx, input.data(), input.size());
    EVP_DigestFinal_ex(ctx, hash.data(), &length);
    EVP_MD_CTX_free(ctx);

    hash.resize(length);  // Trim output to actual hash size
    return hash;
}

std::string Keccak::keccak256(const std::string& input) {
    std::vector<uint8_t> rawHash = keccak256_raw(std::vector<uint8_t>(input.begin(), input.end()));

    std::ostringstream hexStream;
    for (uint8_t byte : rawHash) {
        hexStream << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }

    return hexStream.str();
}
