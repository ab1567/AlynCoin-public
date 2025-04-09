#include "winterfell_recursive.h"
#include <cstring>
#include <iostream>

extern "C" {
    uint8_t* compose_recursive_proof_ffi(const uint8_t* proof, size_t len, const uint8_t* hash);
}

std::string WinterfellStark::generateRecursiveProof(const std::string& innerProof, const std::string& expectedHashHex) {
    if (innerProof.empty() || expectedHashHex.empty()) {
        std::cerr << "[zkSTARK] ❌ Invalid input for recursive proof generation.\n";
        return "";
    }

    // Convert hex string into 32-byte hash
    uint8_t hash[32];
    std::memset(hash, 0, sizeof(hash));
    for (size_t i = 0; i < expectedHashHex.size() && i < 64; i += 2) {
        std::string byteStr = expectedHashHex.substr(i, 2);
        hash[i / 2] = static_cast<uint8_t>(std::stoi(byteStr, nullptr, 16));
    }

    const uint8_t* innerData = reinterpret_cast<const uint8_t*>(innerProof.data());
    uint8_t* result = compose_recursive_proof_ffi(innerData, innerProof.size(), hash);

    if (!result) {
        std::cerr << "[zkSTARK] ❌ Recursive proof generation failed.\n";
        return "";
    }

    std::string recursiveProof(reinterpret_cast<char*>(result));
    free(result);
    return recursiveProof;
}

