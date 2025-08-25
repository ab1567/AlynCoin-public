#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace WalletCrypto {
struct FileHeader {
    char magic[4];      // "ACWK"
    uint8_t version;    // currently 1
    uint8_t alg_id;     // algorithm identifier
    uint32_t mem_mib;   // Argon2id memory cost in MiB
    uint32_t time_cost; // Argon2id time cost
    char profile[16];   // profile name (null terminated)
    unsigned char salt[16];
    unsigned char nonce[24];
};

// Encrypt plaintext and store to path using Argon2id + XChaCha20-Poly1305.
bool encryptToFile(const std::string &path,
                   const std::vector<unsigned char> &plaintext,
                   const std::string &passphrase,
                   const std::string &profile,
                   uint8_t algId);

// Decrypt file at path into plaintext using provided passphrase.
bool decryptFromFile(const std::string &path,
                     std::vector<unsigned char> &out,
                     const std::string &passphrase);
}
