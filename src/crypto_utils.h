#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#pragma once

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <string>
#include <vector>
#include <optional>
#include "db/db_paths.h"

#define DILITHIUM_PUBLIC_KEY_BYTES 1312
#define DILITHIUM_PRIVATE_KEY_BYTES 2560
#define FALCON_PUBLIC_KEY_BYTES    1793
#define FALCON_PRIVATE_KEY_BYTES   2305

#define KEY_DIR DBPaths::getKeyDir()

struct DilithiumKeyPair {
    std::vector<uint8_t> publicKey;
    std::vector<uint8_t> privateKey;
    std::string publicKeyHex;
    std::string privateKeyHex; // optional
};

struct FalconKeyPair {
    std::vector<uint8_t> publicKey;
    std::vector<uint8_t> privateKey;
    std::string publicKeyHex;
    std::string privateKeyHex; // optional
};

namespace Crypto {
// Hash functions
std::string sha256(const std::string &input);
std::string keccak256(const std::string &input);
std::string blake3(const std::string &input);
std::string hybridHash(const std::string &input);
std::string blake3Hash(const std::string &input);
std::string hybridHashWithDomain(const std::string &input, const std::string &domain);
std::vector<unsigned char> sha256ToBytes(const std::string &input);

void ensureKeysDirectory();

// Address generation
std::string generateAddress(const std::string &publicKey);

// Random util
std::string generateRandomHex(size_t length);

// Private/public‑key helpers
std::string generatePrivateKey(const std::string &user, const std::string &passphrase);
std::vector<unsigned char> getPublicKeyBytes(const std::string &walletAddress);
std::string getPublicKey(const std::string &user);
void generateKeysForUser(const std::string &username);
void ensureUserKeys(const std::string &username);
void ensureMinerKeys();
std::string generateMinerAddress();

// Generic helpers
EVP_PKEY *loadPrivateKey(const std::string &privateKeyPath);
bool fileExists(const std::string &path);
std::string toHex(const std::vector<unsigned char> &data);
std::vector<unsigned char> fromHex(const std::string &hex);

// Base-64 helpers (non‑recursive, only these two signatures!)
std::string base64Encode(const std::string &input, bool wrapLines = true);
std::string base64Decode(const std::string &input, bool inputIsWrapped = true);

std::vector<unsigned char> stringToBytes(const std::string &input);

// Digital‑signature helpers
std::string signMessage(const std::string &message,
                        const std::string &privateKeyPath,
                        bool isFilePath = true);
bool verifyMessage(const std::string &publicKeyPath,
                   const std::string &signature,
                   const std::string &message);

// Post‑quantum key generation
DilithiumKeyPair generateDilithiumKeys(const std::string &username);
FalconKeyPair    generateFalconKeys(const std::string &username);
bool             generatePostQuantumKeys(const std::string &username);

// PQ signatures
std::vector<unsigned char> signWithDilithium(const std::vector<unsigned char> &message,
                                             const std::vector<unsigned char> &privKey);
std::vector<unsigned char> signWithFalcon(const std::vector<unsigned char> &message,
                                          const std::vector<unsigned char> &privKey);

std::vector<unsigned char> getPublicKeyDilithium(const std::string &walletAddress);
std::vector<unsigned char> getPublicKeyFalcon(const std::string &walletAddress);

// PQ verification
bool verifyWithDilithium(const std::vector<unsigned char> &message,
                         const std::vector<unsigned char> &signature,
                         const std::vector<unsigned char> &publicKey);
bool verifyWithFalcon(const std::vector<unsigned char> &message,
                      const std::vector<unsigned char> &signature,
                      const std::vector<unsigned char> &publicKey);

// PQ key loading
DilithiumKeyPair loadDilithiumKeys(const std::string &username);
FalconKeyPair    loadFalconKeys(const std::string &username);

// Protobuf serialization
void serializeKeysToProtobuf(const std::string &privateKeyPath, std::string &output);
bool deserializeKeysFromProtobuf(const std::string &input, std::string &privateKey, std::string &publicKey);

bool isLikelyHex(const std::string& str);
std::optional<std::vector<unsigned char>> safeFromHex(const std::string& hex, const std::string& context = "");
} // namespace Crypto

// Global key-path helpers
std::string getPublicKeyPath(const std::string &username, const std::string &baseDir = KEY_DIR);
std::string getPrivateKeyPath(const std::string &username, const std::string &baseDir = KEY_DIR);

#endif // CRYPTO_UTILS_H
