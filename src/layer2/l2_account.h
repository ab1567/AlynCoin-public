#pragma once
#include <string>
#include <cstdint>

// Represents an L2 account with minimal fields.
struct L2Account {
    std::string address;      // hex-encoded 20-byte address
    std::string codeHash;     // hex-encoded hash of Wasm code
    std::string storageRoot;  // hex-encoded root of storage SMT
    uint64_t nonce{0};
    uint64_t balance{0};
};
