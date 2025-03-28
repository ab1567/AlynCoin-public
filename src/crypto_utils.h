#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <string>
#include <vector>

// Directory for key storage
#define KEY_DIR "/root/.alyncoin/keys/"

struct DilithiumKeyPair {
  std::vector<uint8_t> publicKey;
  std::vector<uint8_t> privateKey;
};

struct FalconKeyPair {
  std::vector<uint8_t> publicKey;
  std::vector<uint8_t> privateKey;
};

namespace Crypto {
// ✅ Hash Functions
std::string sha256(const std::string &input);
std::string keccak256(const std::string &input);
std::string blake3(const std::string &input);
std::string hybridHash(const std::string &input);
std::string blake3Hash(const std::string &input);
std::string hybridHashWithDomain(const std::string &input,
                                 const std::string &domain);
void ensureKeysDirectory();
// ✅ Address Generation
std::string generateAddress(const std::string &publicKey);
// ✅ Random
std::string generateRandomHex(size_t length);
// ✅ Private/Public Key Handling
std::string generatePrivateKey(const std::string &user,
                               const std::string &passphrase);
  std::vector<unsigned char> getPublicKeyBytes(const std::string &walletAddress);
std::string getPublicKey(const std::string &user);
void generateKeysForUser(const std::string &username);
void ensureUserKeys(const std::string &username);
void ensureMinerKeys();
std::string generateMinerAddress();

// ✅ Helper Functions
EVP_PKEY *loadPrivateKey(const std::string &privateKeyPath);
bool fileExists(const std::string &path);
std::string toHex(const std::vector<unsigned char> &data);
std::vector<unsigned char> fromHex(const std::string &hex);
std::string base64Encode(const std::string &input);
std::string base64Decode(const std::string &input);
std::vector<unsigned char> stringToBytes(const std::string &input);
// ✅ Digital Signature Functions
std::string signMessage(const std::string &message,
                        const std::string &privateKeyPath,
                        bool isFilePath = true);
bool verifyMessage(const std::string &publicKeyPath,
                   const std::string &signature, const std::string &message);

// ✅ Post-Quantum Keys (Return full keypair structs)
DilithiumKeyPair generateDilithiumKeys(const std::string &username);
FalconKeyPair generateFalconKeys(const std::string &username);

// ✅ PQ Signatures (Raw vector-based)
std::vector<unsigned char>
signWithDilithium(const std::vector<unsigned char> &message,
                  const std::vector<unsigned char> &privKey);
std::vector<unsigned char>
signWithFalcon(const std::vector<unsigned char> &message,
               const std::vector<unsigned char> &privKey);

std::vector<unsigned char> getPublicKeyDilithium(const std::string &walletAddress);
std::vector<unsigned char> getPublicKeyFalcon(const std::string &walletAddress);

// ✅ PQ Verification (Overloaded with username-based as well)
bool verifyWithDilithium(const std::vector<unsigned char> &message,
                         const std::vector<unsigned char> &signature,
                         const std::vector<unsigned char> &publicKey);

bool verifyWithFalcon(const std::vector<unsigned char> &message,
                      const std::vector<unsigned char> &signature,
                      const std::vector<unsigned char> &publicKey);

// ✅ PQ Key Loading
DilithiumKeyPair loadDilithiumKeys(const std::string &username);
FalconKeyPair loadFalconKeys(const std::string &username);

// ✅ Protobuf Serialization
void serializeKeysToProtobuf(const std::string &privateKeyPath,
                             std::string &output);
bool deserializeKeysFromProtobuf(const std::string &input,
                                 std::string &privateKey,
                                 std::string &publicKey);

} // namespace Crypto
// ✅ Global Key Path Helpers
std::string getPublicKeyPath(const std::string &username,
                             const std::string &baseDir = KEY_DIR);
std::string getPrivateKeyPath(const std::string &username,
                              const std::string &baseDir = KEY_DIR);

#endif // CRYPTO_UTILS_H
