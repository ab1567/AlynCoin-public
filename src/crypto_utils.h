#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "wallet.h"
#include <string>
#include <vector>
#include "crypto_protos.pb.h"  // ✅ Include Protobuf definitions

namespace Crypto {
    // ✅ Hash Functions
    std::string sha256(const std::string& input);
    std::string keccak256(const std::string& input);
    std::string blake3(const std::string& input);
    std::string hybridHash(const std::string& input);

    // ✅ Address Generation
    std::string generateAddress(const std::string& publicKey);

    // ✅ Private/Public Key Handling
    std::string generatePrivateKey(const std::string& filename);
    std::string getPublicKey(const std::string& privateKeyPath);
    void generateKeysForUser(const std::string& username);
    std::string generateMinerAddress(const std::string& username);
    void ensureMinerKeys();

    // ✅ Helper Functions
    std::string bytesToHex(const std::vector<unsigned char>& bytes);
    std::vector<unsigned char> hexToBytes(const std::string& hex);
    EVP_PKEY* loadPrivateKey(const std::string& privateKeyPath);

    std::string base64Encode(const std::string& input);
    std::string base64Decode(const std::string& input);

    // ✅ Digital Signature Functions
    std::string signMessage(const std::string& message, const std::string& privateKeyPath, bool useManualSignature = false);
    bool verifyMessage(const std::string& publicKeyPath, const std::string& signatureHex, const std::string& message);

    // ✅ Protobuf Serialization for Keys
    void serializeKeysToProtobuf(const std::string& privateKeyPath, std::string& output);
    bool deserializeKeysFromProtobuf(const std::string& input, std::string& privateKey, std::string& publicKey);
    std::string decryptFile(const std::string& filePath, const std::string& password);
        bool fileExists(const std::string& path);

      void ensureUserKeys(const std::string& username);
}

// ✅ Add this globally (outside namespace)
std::string getPublicKeyPath(const std::string& username, const std::string& baseDir = "/root/.alyncoin/keys/");
std::string getPrivateKeyPath(const std::string& username, const std::string& baseDir = "/root/.alyncoin/keys/");

#endif // CRYPTO_UTILS_H
