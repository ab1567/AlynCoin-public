#include "generated/crypto_protos.pb.h"
#include "crypto_utils.h"
#include "blake3.h"
#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <random>
#include <sstream>
#include <thread>
#include <unistd.h>
#include <vector>
extern "C" {
#include "api.h"
#include "sign.h"
}
#define pqcrystals_dilithium2_ref_PUBLICKEYBYTES CRYPTO_PUBLICKEYBYTES
#define falcon_crypto_sign_keypair PQCLEAN_FALCON1024_CLEAN_crypto_sign_keypair
#define falcon_crypto_sign_signature                                           \
  PQCLEAN_FALCON1024_CLEAN_crypto_sign_signature
#define falcon_crypto_sign_verify PQCLEAN_FALCON1024_CLEAN_crypto_sign_verify


namespace fs = std::filesystem;

namespace Crypto {

// ✅ SHA-256 Implementation
std::string sha256(const std::string &input) {
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  const EVP_MD *md = EVP_sha256();
  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned int length = 0;

  EVP_DigestInit_ex(ctx, md, nullptr);
  EVP_DigestUpdate(ctx, input.data(), input.size());
  EVP_DigestFinal_ex(ctx, hash, &length);
  EVP_MD_CTX_free(ctx);

  std::ostringstream hexStream;
  for (unsigned int i = 0; i < length; i++) {
    hexStream << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
  }

  return hexStream.str();
}

// ✅ Keccak-256 Implementation
std::string keccak256(const std::string &input) {
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  const EVP_MD *md = EVP_get_digestbyname("SHA3-256"); // Changed here
  if (md == nullptr) {
    throw std::runtime_error("Keccak-256 (SHA3-256) not available");
  }

  EVP_DigestInit_ex(ctx, md, nullptr);
  EVP_DigestUpdate(ctx, input.data(), input.size());

  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned int lengthOfHash = 0;
  EVP_DigestFinal_ex(ctx, hash, &lengthOfHash);
  EVP_MD_CTX_free(ctx);

  std::stringstream ss;
  for (unsigned int i = 0; i < lengthOfHash; ++i) {
    ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
  }
  return ss.str();
}

// ✅ BLAKE3 Implementation
std::string blake3(const std::string &input) {
  blake3_hasher hasher;
  blake3_hasher_init(&hasher);
  blake3_hasher_update(&hasher, input.data(), input.size());

  std::vector<uint8_t> output(BLAKE3_OUT_LEN);
  blake3_hasher_finalize(&hasher, output.data(), BLAKE3_OUT_LEN);

  std::stringstream ss;
  for (auto byte : output) {
    ss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
  }
  return ss.str();
}

// ✅ Hybrid Hashing (Keccak-256 over BLAKE3)
std::string hybridHash(const std::string &input) {
  return keccak256(blake3(input));
}
// ✅ Generate Address Using Hybrid Hash
std::string generateAddress(const std::string &publicKey) {
  return hybridHash(publicKey).substr(0, 40);
}

// --- Dilithium Key Generation ---
DilithiumKeyPair generateDilithiumKeys(const std::string &username) {
  std::cout << "[DEBUG] Attempting to generate Dilithium keys for user: " << username << std::endl;
  DilithiumKeyPair keypair;
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];

  if (crypto_sign_keypair(pk, sk) == 0) {
    keypair.publicKey.assign(pk, pk + sizeof(pk));
    keypair.privateKey.assign(sk, sk + sizeof(sk));

    std::string pubPath = KEY_DIR + username + "_dilithium.pub";
    std::string privPath = KEY_DIR + username + "_dilithium.key";

    std::ofstream pub(pubPath, std::ios::binary);
    std::ofstream priv(privPath, std::ios::binary);

    pub.write((char *)pk, sizeof(pk));
    priv.write((char *)sk, sizeof(sk));

    std::cout << "✅ [DEBUG] Dilithium keys generated and saved to:\n";
    std::cout << "    " << pubPath << "\n    " << privPath << std::endl;
  } else {
    std::cerr << "❌ [ERROR] Failed to generate Dilithium keypair for " << username << "\n";
  }

  return keypair;
}

// --- Falcon Key Generation ---
FalconKeyPair generateFalconKeys(const std::string &username) {
  std::cout << "[DEBUG] Attempting to generate Falcon keys for user: " << username << std::endl;
  FalconKeyPair keypair;
  uint8_t pk[PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES];

  if (PQCLEAN_FALCON1024_CLEAN_crypto_sign_keypair(pk, sk) == 0) {
    keypair.publicKey.assign(pk, pk + sizeof(pk));
    keypair.privateKey.assign(sk, sk + sizeof(sk));

    std::string pubPath = KEY_DIR + username + "_falcon.pub";
    std::string privPath = KEY_DIR + username + "_falcon.key";

    std::ofstream pub(pubPath, std::ios::binary);
    std::ofstream priv(privPath, std::ios::binary);

    pub.write((char *)pk, sizeof(pk));
    priv.write((char *)sk, sizeof(sk));

    std::cout << "✅ [DEBUG] Falcon keys generated and saved to:\n";
    std::cout << "    " << pubPath << "\n    " << privPath << std::endl;
  } else {
    std::cerr << "❌ [ERROR] Failed to generate Falcon keypair for " << username << "\n";
  }

  return keypair;
}

// --- Dilithium Signing ---
std::vector<unsigned char>
signWithDilithium(const std::vector<unsigned char> &message,
                  const std::vector<unsigned char> &privKey) {
  if (privKey.size() != CRYPTO_SECRETKEYBYTES) {
    std::cerr << "[ERROR] signWithDilithium() - Private key size mismatch!\n";
    return {};
  }

  // Max signature size is safe at 2701, but we'll cap at 2700 to prevent overflow
  std::vector<unsigned char> signature(2700);
  size_t siglen = 0;

  int ret = crypto_sign_signature(
      signature.data(), &siglen,
      message.data(), message.size(),
      nullptr, 0, // context = NULL
      privKey.data());

  if (ret != 0) {
    std::cerr << "❌ [ERROR] Dilithium signing failed! ret=" << ret << "\n";
    return {};
  }

  if (siglen == 0 || siglen > signature.size()) {
    std::cerr << "❌ [ERROR] Invalid signature length: " << siglen
              << " (max allowed: " << signature.size() << ")\n";
    return {};
  }

  signature.resize(siglen);
  std::cout << "✅ [DEBUG] Dilithium signature generated. Length: " << siglen << "\n";
  return signature;
}

// --- Dilithium Verification ---
bool verifyWithDilithium(const std::vector<unsigned char> &message,
                         const std::vector<unsigned char> &signature,
                         const std::vector<unsigned char> &publicKey) {
  if (signature.empty() || message.empty() || publicKey.empty())
    return false;

  if (publicKey.size() != CRYPTO_PUBLICKEYBYTES)
    return false;

  int result = crypto_sign_verify(signature.data(), signature.size(),
                                  message.data(), message.size(),
                                  nullptr, 0, publicKey.data());

  return result == 0;
}

// --- Falcon Signing ---
std::vector<unsigned char>
signWithFalcon(const std::vector<unsigned char> &message,
               const std::vector<unsigned char> &privKey) {
  const size_t expectedPrivSize = PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES;

  if (privKey.size() != expectedPrivSize) {
    std::cerr << "[ERROR] signWithFalcon() - Private key size mismatch! Expected: "
              << expectedPrivSize << ", Got: " << privKey.size() << "\n";
    return {};
  }

  if (message.size() != 32) {
    std::cerr << "[ERROR] signWithFalcon() - Message hash size invalid: " << message.size() << " (expected 32)\n";
    return {};
  }

  size_t maxSigLen = 1330;
  std::vector<unsigned char> signature(maxSigLen);
  size_t actualSigLen = 0;

  std::cout << "[DEBUG] Calling Falcon crypto_sign_signature... (message.size=" << message.size()
            << ", privKey.size=" << privKey.size() << ")\n";

  try {
    int ret = PQCLEAN_FALCON1024_CLEAN_crypto_sign_signature(
        signature.data(), &actualSigLen,
        message.data(), message.size(),
        privKey.data());

    if (ret != 0) {
      std::cerr << "❌ [ERROR] Falcon signing failed! Return code: " << ret << "\n";
      return {};
    }

    if (actualSigLen == 0 || actualSigLen > maxSigLen) {
      std::cerr << "❌ [ERROR] Falcon signature length invalid: " << actualSigLen << "\n";
      return {};
    }

    signature.resize(actualSigLen);
    std::cout << "✅ [DEBUG] Falcon signature generated. Length: " << actualSigLen << "\n";
    return signature;

  } catch (const std::exception &ex) {
    std::cerr << "❌ [EXCEPTION] Falcon signing threw exception: " << ex.what() << "\n";
    return {};
  } catch (...) {
    std::cerr << "❌ [FATAL] Unknown Falcon signing crash caught!\n";
    return {};
  }
}

// --- ✅ Falcon Verification ---
bool verifyWithFalcon(const std::vector<unsigned char> &message,
                      const std::vector<unsigned char> &signature,
                      const std::vector<unsigned char> &publicKey) {
  if (signature.empty() || message.empty() || publicKey.empty())
    return false;

  if (publicKey.size() != PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES)
    return false;

  int result = PQCLEAN_FALCON1024_CLEAN_crypto_sign_verify(
      signature.data(), signature.size(),
      message.data(), message.size(),
      publicKey.data());

  return result == 0;
}

// --- Public Key Extraction ---
std::string extractDilithiumPublicKey(const std::string &username) {
  std::string pubPath = KEY_DIR + username + "_dilithium.pub";
  if (!Crypto::fileExists(pubPath))
    return "";
  std::ifstream pubFile(pubPath, std::ios::binary);
  std::stringstream buffer;
  buffer << pubFile.rdbuf();
  return buffer.str();
}

std::string extractFalconPublicKey(const std::string &username) {
  std::string pubPath = KEY_DIR + username + "_falcon.pub";
  if (!Crypto::fileExists(pubPath))
    return "";
  std::ifstream pubFile(pubPath, std::ios::binary);
  std::stringstream buffer;
  buffer << pubFile.rdbuf();
  return buffer.str();
}
// --- Binary Public Key Loaders (for signature verification) ---
std::vector<unsigned char> getPublicKeyDilithium(const std::string &walletAddress) {
  std::string pubPath = KEY_DIR + walletAddress + "_dilithium.pub";
  std::ifstream pubFile(pubPath, std::ios::binary);
  if (!pubFile) return {};

  std::vector<unsigned char> buffer((std::istreambuf_iterator<char>(pubFile)),
                                    std::istreambuf_iterator<char>());
  return buffer;
}

std::vector<unsigned char> getPublicKeyFalcon(const std::string &walletAddress) {
  std::string pubPath = KEY_DIR + walletAddress + "_falcon.pub";
  std::ifstream pubFile(pubPath, std::ios::binary);
  if (!pubFile) return {};

  std::vector<unsigned char> buffer((std::istreambuf_iterator<char>(pubFile)),
                                    std::istreambuf_iterator<char>());
  return buffer;
}

// --- Key Loading ---
DilithiumKeyPair loadDilithiumKeys(const std::string &username) {
  DilithiumKeyPair keypair;

  std::string privPath = KEY_DIR + username + "_dilithium.key";
  std::string pubPath  = KEY_DIR + username + "_dilithium.pub";

  std::ifstream priv(privPath, std::ios::binary);
  std::ifstream pub(pubPath, std::ios::binary);

  if (pub && priv) {
    std::vector<unsigned char> pubBytes((std::istreambuf_iterator<char>(pub)),
                                        std::istreambuf_iterator<char>());
    std::vector<unsigned char> privBytes((std::istreambuf_iterator<char>(priv)),
                                         std::istreambuf_iterator<char>());
    if (!pubBytes.empty() && !privBytes.empty()) {
      keypair.publicKey = pubBytes;
      keypair.privateKey = privBytes;
    }
  }

  return keypair;
}

//
FalconKeyPair loadFalconKeys(const std::string &username) {
  FalconKeyPair keypair;
  std::string privPath = KEY_DIR + username + "_falcon.key";
  std::string pubPath = KEY_DIR + username + "_falcon.pub";

  std::ifstream pub(pubPath, std::ios::binary);
  std::ifstream priv(privPath, std::ios::binary);

  if (pub && priv) {
    std::vector<unsigned char> pubBytes((std::istreambuf_iterator<char>(pub)),
                                        std::istreambuf_iterator<char>());
    std::vector<unsigned char> privBytes((std::istreambuf_iterator<char>(priv)),
                                         std::istreambuf_iterator<char>());
    keypair.publicKey = pubBytes;
    keypair.privateKey = privBytes;
  }
  return keypair;
}
// buff conversion
void serializeKeysToProtobuf(const std::string &privateKeyPath,
                             std::string &output) {
  alyncoin::CryptoKeysProto keyProto;

  std::ifstream privFile(privateKeyPath);
  if (privFile) {
    std::stringstream buffer;
    buffer << privFile.rdbuf();
    keyProto.set_private_key(buffer.str());
    privFile.close();
  } else {
    std::cerr << "❌ Error: Cannot open private key file: " << privateKeyPath
              << std::endl;
    return;
  }

  std::string publicKeyPath = privateKeyPath;
  size_t pos = publicKeyPath.find("_private.pem");
  if (pos != std::string::npos) {
    publicKeyPath.replace(pos, 12, "_public.pem");
  }

  std::ifstream pubFile(publicKeyPath);
  if (pubFile) {
    std::stringstream buffer;
    buffer << pubFile.rdbuf();
    keyProto.set_public_key(buffer.str());
    pubFile.close();
  } else {
    std::cerr << "⚠️ Warning: Cannot open public key file: " << publicKeyPath
              << std::endl;
  }

  keyProto.SerializeToString(&output);
}

bool deserializeKeysFromProtobuf(const std::string &input,
                                 std::string &privateKey,
                                 std::string &publicKey) {
  alyncoin::CryptoKeysProto keyProto;
  if (!keyProto.ParseFromString(input)) {
    std::cerr << "❌ Error: Failed to parse Protobuf key data!" << std::endl;
    return false;
  }

  privateKey = keyProto.private_key();
  publicKey = keyProto.public_key();
  return true;
}

// Convert bytes to hex string
std::string toHex(const std::vector<unsigned char> &data) {
  static const char hex_chars[] = "0123456789abcdef";
  std::string hex;
  hex.reserve(data.size() * 2);
  for (unsigned char byte : data) {
    hex.push_back(hex_chars[(byte >> 4) & 0x0F]);
    hex.push_back(hex_chars[byte & 0x0F]);
  }
  return hex;
}
// Convert hex string back to bytes
std::vector<unsigned char> fromHex(const std::string &hex) {
  std::vector<unsigned char> bytes;
  bytes.reserve(hex.length() / 2);
  for (size_t i = 0; i < hex.length(); i += 2) {
    unsigned char byte =
        (unsigned char)strtol(hex.substr(i, 2).c_str(), nullptr, 16);
    bytes.push_back(byte);
  }
  return bytes;
}
//
std::vector<unsigned char> stringToBytes(const std::string &input) {
    return std::vector<unsigned char>(input.begin(), input.end());
}

// ✅ Ensure "keys" directory exists
void ensureKeysDirectory() {
  if (!fs::exists(KEY_DIR)) {
    fs::create_directories(KEY_DIR);
  }
}
// ✅ Generate Private & Public Key Pair for a User (with Debugging)
void generateKeysForUser(const std::string &username) {
  std::cout << "[DEBUG] Ensuring keys directory exists..." << std::endl;
  ensureKeysDirectory();

  std::string cleanUsername = username;
  std::replace(cleanUsername.begin(), cleanUsername.end(), ' ', '_');

  std::string privateKeyPath = KEY_DIR + cleanUsername + "_private.pem";
  std::string publicKeyPath = KEY_DIR + cleanUsername + "_public.pem";

  std::cout << "[DEBUG] Private key path: " << privateKeyPath << std::endl;
  std::cout << "[DEBUG] Public key path: " << publicKeyPath << std::endl;

  if (fs::exists(privateKeyPath) && fs::exists(publicKeyPath)) {
    std::cout << "🔑 Keys for user " << cleanUsername
              << " already exist. Skipping generation.\n";
    return;
  }

  std::cout << "🔑 Generating new keys for user: " << cleanUsername << "\n";

  std::string privCmd = "openssl genpkey -algorithm RSA -out \"" +
                        privateKeyPath + "\" -pkeyopt rsa_keygen_bits:2048";
  std::string pubCmd = "openssl rsa -in \"" + privateKeyPath +
                       "\" -pubout -out \"" + publicKeyPath + "\"";

  std::cout << "[DEBUG] Running private key generation command: " << privCmd
            << std::endl;
  int privStatus = system(privCmd.c_str());
  if (privStatus != 0) {
    std::cerr << "❌ [ERROR] Private key generation failed for user: "
              << cleanUsername << std::endl;
    return;
  }
  std::cout << "[DEBUG] Private key generated successfully." << std::endl;

  std::cout << "[DEBUG] Running public key extraction command: " << pubCmd
            << std::endl;
  int pubStatus = system(pubCmd.c_str());
  if (pubStatus != 0) {
    std::cerr << "❌ [ERROR] Public key extraction failed for user: "
              << cleanUsername << std::endl;
    return;
  }
  std::cout << "[DEBUG] Public key generated successfully." << std::endl;

  // Final check to ensure both files now exist
  if (fs::exists(privateKeyPath) && fs::exists(publicKeyPath)) {
    std::cout << "✅ [INFO] Successfully generated keys for user: "
              << cleanUsername << std::endl;
  } else {
    std::cerr << "❌ [ERROR] Key files missing after generation attempt!"
              << std::endl;
  }
}

// ✅ Generate Private Key (Auto-Creation)
std::string generatePrivateKey(const std::string &user,
                               const std::string &passphrase) {
  ensureKeysDirectory();
  const std::string keyDir = "/root/.alyncoin/keys/";
  const std::string privateKeyPath = keyDir + user + "_private.pem";

  // If the private key already exists, read and return its contents
  if (fs::exists(privateKeyPath)) {
    std::ifstream privFile(privateKeyPath);
    std::stringstream buffer;
    buffer << privFile.rdbuf();
    return buffer.str();
  }

  // Create a new RSA key
  EVP_PKEY *pkey = nullptr;
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
  if (!ctx) {
    std::cerr << "❌ Error: Failed to create EVP_PKEY_CTX." << std::endl;
    return "";
  }

  if (EVP_PKEY_keygen_init(ctx) <= 0 ||
      EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 4096) <= 0) {
    std::cerr << "❌ Error: Failed to initialize keygen context or set key length." << std::endl;
    EVP_PKEY_CTX_free(ctx);
    return "";
  }

  if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
    std::cerr << "❌ Error: Key generation failed." << std::endl;
    EVP_PKEY_CTX_free(ctx);
    return "";
  }
  EVP_PKEY_CTX_free(ctx);

  // Write the private key to a PEM file WITHOUT encryption
  BIO *bio = BIO_new_file(privateKeyPath.c_str(), "w");
  if (!bio) {
    std::cerr << "❌ Error: Failed to create file BIO for path: " << privateKeyPath << std::endl;
    std::cerr << "    ➤ Check if directory exists, or if the file is corrupted or locked.\n";
    EVP_PKEY_free(pkey);
    return "";
  }

  if (!PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr)) {
    std::cerr << "❌ Error: Failed to write private key to file without encryption." << std::endl;
    BIO_free(bio);
    EVP_PKEY_free(pkey);
    return "";
  }
  BIO_free(bio);

  // Convert the private key to a string (again without encryption)
  bio = BIO_new(BIO_s_mem());
  if (!bio) {
    std::cerr << "❌ Error: Failed to create memory BIO." << std::endl;
    EVP_PKEY_free(pkey);
    return "";
  }

  if (!PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr)) {
    std::cerr << "❌ Error: Failed to write private key to memory without encryption." << std::endl;
    BIO_free(bio);
    EVP_PKEY_free(pkey);
    return "";
  }

  char *keyData;
  long keySize = BIO_get_mem_data(bio, &keyData);
  std::string privateKey(keyData, keySize);

  EVP_PKEY_free(pkey);
  BIO_free(bio);

  return privateKey;
}

// ✅ Get Public Key from Private Key (Auto-Creation)
std::string getPublicKey(const std::string &user) {
  ensureKeysDirectory();
  std::string privateKeyPath = getPrivateKeyPath(user);
  std::string publicKeyPath = KEY_DIR + user + "_public.pem";

  // ✅ Check if public key already exists
  if (fs::exists(publicKeyPath)) {
    std::ifstream pubFile(publicKeyPath);
    std::stringstream buffer;
    buffer << pubFile.rdbuf();
    return buffer.str();
  }

  // ✅ If private key is missing, generate it first
  if (!fs::exists(privateKeyPath)) {
    std::cerr << "⚠️ [WARNING] Private key missing for " << user
              << ". Generating new key pair...\n";
    Crypto::generateKeysForUser(user);
  }

  // ✅ Generate Public Key from Private Key
  std::string cmd = "openssl rsa -in \"" + privateKeyPath +
                    "\" -pubout -out \"" + publicKeyPath + "\"";
  if (system(cmd.c_str()) != 0) {
    std::cerr << "❌ [ERROR] Failed to generate public key for " << user
              << "!\n";
    return "";
  }

  // ✅ Read and return public key content
  std::ifstream pubFile(publicKeyPath);
  if (!pubFile) {
    std::cerr << "❌ [ERROR] Failed to open generated public key file!\n";
    return "";
  }

  std::stringstream buffer;
  buffer << pubFile.rdbuf();
  return buffer.str();
}

// ✅ Clean loadPrivateKey() with file existence check
EVP_PKEY *loadPrivateKey(const std::string &privateKeyPath) {
  if (!fs::exists(privateKeyPath)) {
    std::cerr << "❌ [ERROR] Private key file missing: " << privateKeyPath
              << "\n";
    return nullptr;
  }

  FILE *fp = fopen(privateKeyPath.c_str(), "r");
  if (!fp) {
    std::cerr << "❌ [ERROR] Cannot open private key file: " << privateKeyPath
              << "\n";
    return nullptr;
  }

  EVP_PKEY *privateKey = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
  fclose(fp);

  if (!privateKey) {
    std::cerr << "❌ [ERROR] Failed to parse private key!\n";
  }
  return privateKey;
}

// ✅ Ensure Wallet Keys Exist for Any User (Auto-Handling)
void ensureUserKeys(const std::string &username) {
  ensureKeysDirectory();
  generateKeysForUser(username);
}
//
bool fileExists(const std::string &path) {
  return std::filesystem::exists(path);
}
// ✅ Ensure Miner Keys Exist (Auto-Handling)
void ensureMinerKeys() {
  ensureKeysDirectory();
  std::string minerPrivateKey = generatePrivateKey("miner", "defaultpass");
  std::string minerPublicKey = getPublicKey("miner");

  if (minerPrivateKey.empty() || minerPublicKey.empty()) {
    std::cerr << "❌ Critical Error: Miner keys could not be generated!"
              << std::endl;
  } else {
    std::cout << "✅ Miner keys verified and exist.\n";
  }
}
// ✅ Generate Miner Address from Public Key
std::string generateMinerAddress() {
  std::string publicKey = getPublicKey("miner");
  if (publicKey.empty()) {
    std::cerr
        << "❌ Error: Cannot generate miner address. Public key missing!\n";
    return "";
  }
  return Crypto::generateAddress(publicKey);
}

// ✅ Base64 Encode
std::string base64Encode(const std::string &input) {
  BIO *bio, *b64;
  BUF_MEM *bufferPtr;

  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new(BIO_s_mem());
  bio = BIO_push(b64, bio);
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
  BIO_write(bio, input.data(), input.size());
  BIO_flush(bio);
  BIO_get_mem_ptr(bio, &bufferPtr);

  std::string output(bufferPtr->data, bufferPtr->length);
  BIO_free_all(bio);
  return output;
}

// ✅ Base64 Decode
std::string base64Decode(const std::string &input) {
  BIO *bio, *b64;
  std::vector<char> buffer(input.size());

  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new_mem_buf(input.data(), input.size());
  bio = BIO_push(b64, bio);
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

  int decodedSize = BIO_read(bio, buffer.data(), input.size());
  BIO_free_all(bio);

  if (decodedSize <= 0)
    return "";
  return std::string(buffer.data(), decodedSize);
}
//
bool encryptFile(const std::string &inputFilePath,
                 const std::string &outputFilePath,
                 const std::string &publicKeyPath) {
  FILE *pubKeyFile = fopen(publicKeyPath.c_str(), "rb");
  if (!pubKeyFile) {
    std::cerr << "Unable to open public key file: " << publicKeyPath
              << std::endl;
    return false;
  }

  EVP_PKEY *pubKey = PEM_read_PUBKEY(pubKeyFile, nullptr, nullptr, nullptr);
  fclose(pubKeyFile);

  if (!pubKey) {
    std::cerr << "Error reading public key from file." << std::endl;
    return false;
  }

  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pubKey, nullptr);
  if (!ctx || EVP_PKEY_encrypt_init(ctx) <= 0) {
    std::cerr << "Error initializing encryption context." << std::endl;
    EVP_PKEY_free(pubKey);
    return false;
  }

  // Read input file
  std::ifstream inputFile(inputFilePath, std::ios::binary);
  if (!inputFile) {
    std::cerr << "Unable to open input file: " << inputFilePath << std::endl;
    EVP_PKEY_free(pubKey);
    EVP_PKEY_CTX_free(ctx);
    return false;
  }
  std::string inputData((std::istreambuf_iterator<char>(inputFile)),
                        std::istreambuf_iterator<char>());
  inputFile.close();

  size_t outLen = 0;
  if (EVP_PKEY_encrypt(
          ctx, nullptr, &outLen,
          reinterpret_cast<const unsigned char *>(inputData.c_str()),
          inputData.size()) <= 0) {
    std::cerr << "Error calculating encrypted size." << std::endl;
    EVP_PKEY_free(pubKey);
    EVP_PKEY_CTX_free(ctx);
    return false;
  }

  std::vector<unsigned char> encryptedData(outLen);
  if (EVP_PKEY_encrypt(
          ctx, encryptedData.data(), &outLen,
          reinterpret_cast<const unsigned char *>(inputData.c_str()),
          inputData.size()) <= 0) {
    std::cerr << "Error during encryption." << std::endl;
    EVP_PKEY_free(pubKey);
    EVP_PKEY_CTX_free(ctx);
    return false;
  }

  EVP_PKEY_free(pubKey);
  EVP_PKEY_CTX_free(ctx);

  // Write encrypted data
  std::ofstream outputFile(outputFilePath, std::ios::binary);
  if (!outputFile) {
    std::cerr << "Unable to open output file: " << outputFilePath << std::endl;
    return false;
  }

  outputFile.write(reinterpret_cast<const char *>(encryptedData.data()),
                   outLen);
  outputFile.close();

  return true;
}
//
bool decryptFile(const std::string &inputFilePath,
                 const std::string &outputFilePath,
                 const std::string &privateKeyPath) {
  FILE *privKeyFile = fopen(privateKeyPath.c_str(), "rb");
  if (!privKeyFile) {
    std::cerr << "Unable to open private key file: " << privateKeyPath
              << std::endl;
    return false;
  }

  EVP_PKEY *privKey =
      PEM_read_PrivateKey(privKeyFile, nullptr, nullptr, nullptr);
  fclose(privKeyFile);

  if (!privKey) {
    std::cerr << "Error reading private key from file." << std::endl;
    return false;
  }

  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(privKey, nullptr);
  if (!ctx || EVP_PKEY_decrypt_init(ctx) <= 0) {
    std::cerr << "Error initializing decryption context." << std::endl;
    EVP_PKEY_free(privKey);
    return false;
  }

  // Read encrypted file
  std::ifstream inputFile(inputFilePath, std::ios::binary);
  if (!inputFile) {
    std::cerr << "Unable to open input file: " << inputFilePath << std::endl;
    EVP_PKEY_free(privKey);
    EVP_PKEY_CTX_free(ctx);
    return false;
  }
  std::string encryptedData((std::istreambuf_iterator<char>(inputFile)),
                            std::istreambuf_iterator<char>());
  inputFile.close();

  size_t outLen = 0;
  if (EVP_PKEY_decrypt(
          ctx, nullptr, &outLen,
          reinterpret_cast<const unsigned char *>(encryptedData.c_str()),
          encryptedData.size()) <= 0) {
    std::cerr << "Error calculating decrypted size." << std::endl;
    EVP_PKEY_free(privKey);
    EVP_PKEY_CTX_free(ctx);
    return false;
  }

  std::vector<unsigned char> decryptedData(outLen);
  if (EVP_PKEY_decrypt(
          ctx, decryptedData.data(), &outLen,
          reinterpret_cast<const unsigned char *>(encryptedData.c_str()),
          encryptedData.size()) <= 0) {
    std::cerr << "Error during decryption." << std::endl;
    EVP_PKEY_free(privKey);
    EVP_PKEY_CTX_free(ctx);
    return false;
  }

  EVP_PKEY_free(privKey);
  EVP_PKEY_CTX_free(ctx);

  // Write decrypted data
  std::ofstream outputFile(outputFilePath, std::ios::binary);
  if (!outputFile) {
    std::cerr << "Unable to open output file: " << outputFilePath << std::endl;
    return false;
  }

  outputFile.write(reinterpret_cast<const char *>(decryptedData.data()),
                   outLen);
  outputFile.close();

  return true;
}
//

std::vector<unsigned char> getPublicKeyBytes(const std::string &walletAddress) {
  std::string pubPath = KEY_DIR + walletAddress + "_dilithium.pub";  // or default to dilithium
  std::ifstream pubFile(pubPath, std::ios::binary);

  if (!pubFile.is_open()) {
    std::cerr << "[ERROR] Failed to open public key file: " << pubPath << std::endl;
    return {};
  }

  std::vector<unsigned char> pubKey((std::istreambuf_iterator<char>(pubFile)),
                                    std::istreambuf_iterator<char>());
  return pubKey;
}


// ✅ Fixed & Simplified signMessage()
std::string signMessage(const std::string &message,
                        const std::string &privateKeyPath, bool isFilePath) {
  std::cout << "[DEBUG] Signing message: " << message
            << " using key: " << privateKeyPath << std::endl;
  std::string privateKeyContent;

  if (isFilePath) {
    if (!fs::exists(privateKeyPath)) {
      std::cerr << "❌ [ERROR] Private key file not found: " << privateKeyPath
                << std::endl;
      return "";
    }
    std::ifstream keyFile(privateKeyPath);
    std::stringstream buffer;
    buffer << keyFile.rdbuf();
    privateKeyContent = buffer.str();
    keyFile.close();
  } else {
    privateKeyContent = privateKeyPath;
  }

  if (privateKeyContent.empty()) {
    std::cerr << "❌ [ERROR] Private key is empty!\n";
    return "";
  }

  BIO *bio =
      BIO_new_mem_buf(privateKeyContent.data(), privateKeyContent.size());
  EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
  BIO_free(bio);

  if (!pkey) {
    std::cerr << "❌ [ERROR] Failed to parse private key.\n";
    return "";
  }

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, pkey);
  EVP_DigestSignUpdate(ctx, message.data(), message.size());

  size_t sigLen = 0;
  EVP_DigestSignFinal(ctx, nullptr, &sigLen);
  std::vector<unsigned char> signature(sigLen);
  EVP_DigestSignFinal(ctx, signature.data(), &sigLen);

  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pkey);

  return base64Encode(std::string(signature.begin(), signature.end()));
}

// ✅ Verify a signed message using a public key
bool verifyMessage(const std::string &publicKeyPath,
                   const std::string &signature, const std::string &message) {
  if (!fs::exists(publicKeyPath)) {
    std::cerr << "❌ [ERROR] Public key file not found: " << publicKeyPath
              << std::endl;
    return false;
  }

  std::ifstream pubFile(publicKeyPath);
  std::stringstream buffer;
  buffer << pubFile.rdbuf();
  std::string publicKey = buffer.str();
  pubFile.close();

  if (publicKey.empty()) {
    std::cerr << "❌ [ERROR] Public key is empty: " << publicKeyPath
              << std::endl;
    return false;
  }

  std::string decodedSignature = base64Decode(signature);
  if (decodedSignature.empty()) {
    std::cerr << "❌ [ERROR] Signature decoding failed!" << std::endl;
    return false;
  }

  BIO *bio = BIO_new_mem_buf(publicKey.data(), publicKey.size());
  EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
  BIO_free(bio);

  if (!pkey) {
    std::cerr << "❌ [ERROR] Failed to parse public key." << std::endl;
    return false;
  }

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pkey);
  EVP_DigestVerifyUpdate(ctx, message.c_str(), message.size());

  bool result =
      EVP_DigestVerifyFinal(ctx, (unsigned char *)decodedSignature.data(),
                            decodedSignature.size()) == 1;

  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pkey);

  return result;
}
//
std::string hybridHashWithDomain(const std::string &input,
                                 const std::string &domain) {
  std::string domainSeparator = domain + "|";
  std::string combined = domainSeparator + input;
  return keccak256(blake3Hash(combined));
}
//
std::string generateRandomHex(size_t length) {
  const char *hex_chars = "0123456789abcdef";
  std::string result;
  result.reserve(length);

  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<> dis(0, 15);

  for (size_t i = 0; i < length; ++i) {
    result += hex_chars[dis(gen)];
  }
  return result;
}

std::string blake3Hash(const std::string &input) {
  uint8_t output[BLAKE3_OUT_LEN];
  blake3_hasher hasher;
  blake3_hasher_init(&hasher);
  blake3_hasher_update(&hasher, input.data(), input.size());
  blake3_hasher_finalize(&hasher, output, BLAKE3_OUT_LEN);
  return std::string(reinterpret_cast<char *>(output), BLAKE3_OUT_LEN);
}
//
std::vector<unsigned char> sha256ToBytes(const std::string &input) {
    return fromHex(sha256(input));  // Convert hex → bytes
}

} // namespace Crypto
//
std::string getPrivateKeyPath(const std::string &username,
                              const std::string &baseDir) {
  return baseDir + username + "_private.pem";
}

std::string getPublicKeyPath(const std::string &username,
                             const std::string &baseDir) {
  return baseDir + username + "_public.pem";
}
