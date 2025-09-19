#include <generated/crypto_protos.pb.h>
#include "crypto_utils.h"
#include "blake3.h"
#include "json.hpp"
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
#include <unordered_map>
#include <mutex>
#include <cctype>
#include <stdexcept>
#include <memory>
#ifdef _WIN32
#include <io.h>
#include <Windows.h>
#else
#include <unistd.h>
#endif
#include <vector>
#include <cstdio>
#include "db/db_paths.h"
extern "C" {
#include "crypto/falcon/PQClean/Falcon-1024/clean/api.h"
#include "crypto/dilithium/sign.h"
#include "crypto/dilithium/api.h"
}
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

// ✅ Derive address from raw public key bytes (BLAKE3 -> Keccak256 -> first20)
std::string deriveAddressFromPub(const std::vector<unsigned char>& pubkeyBytes) {
  // Interpret raw bytes as a string for the existing hybridHash pipeline.
  // Note: blake3() returns hex; keccak256() is applied on that hex string.
  // This matches the chain's current address generation semantics.
  std::string raw(reinterpret_cast<const char*>(pubkeyBytes.data()), pubkeyBytes.size());
  return hybridHash(raw).substr(0, 40);
}

namespace {

std::mutex &resolvedCacheMutex() {
  static std::mutex mutex;
  return mutex;
}

std::unordered_map<std::string, std::string> &resolvedCache() {
  static std::unordered_map<std::string, std::string> cache;
  return cache;
}

std::string toLowerCopy(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return value;
}

bool endsWith(const std::string& value, const std::string& suffix) {
  return value.size() >= suffix.size() &&
         value.compare(value.size() - suffix.size(), suffix.size(), suffix) == 0;
}

std::optional<std::string> getCachedResolvedKeyId(const std::string& canonicalLower) {
  std::lock_guard<std::mutex> lock(resolvedCacheMutex());
  auto& cache = resolvedCache();
  auto it = cache.find(canonicalLower);
  if (it != cache.end()) {
    return it->second;
  }
  return std::nullopt;
}

void setCachedResolvedKeyId(const std::string& canonicalLower,
                            const std::string& keyId) {
  std::lock_guard<std::mutex> lock(resolvedCacheMutex());
  resolvedCache()[canonicalLower] = keyId;
}

fs::path walletDataDir() {
  return fs::path(DBPaths::getHomePath()) / ".alyncoin";
}

fs::path walletMapPath() {
  return walletDataDir() / "wallet_map.json";
}

std::mutex& walletMapMutex() {
  static std::mutex mutex;
  return mutex;
}

std::unordered_map<std::string, std::string>& loadWalletMapLocked() {
  static bool loaded = false;
  static std::unordered_map<std::string, std::string> cached;

  if (!loaded) {
    loaded = true;
    const auto path = walletMapPath();
    std::ifstream in(path);
    if (in) {
      nlohmann::json parsed = nlohmann::json::parse(in, nullptr, false);
      if (!parsed.is_discarded() && parsed.is_object()) {
        for (auto it = parsed.begin(); it != parsed.end(); ++it) {
          if (it->is_string()) {
            cached[toLowerCopy(it.key())] = toLowerCopy(it->get<std::string>());
          }
        }
      }
    }
  }

  return cached;
}

void persistWalletMapLocked(const std::unordered_map<std::string, std::string>& map) {
  const auto dir = walletDataDir();
  std::error_code ec;
  fs::create_directories(dir, ec);
  if (ec) {
    std::cerr << "⚠️ Failed to create wallet data directory '" << dir.string()
              << "': " << ec.message() << "\n";
    return;
  }

  nlohmann::json serialized = nlohmann::json::object();
  for (const auto& [address, keyId] : map) {
    serialized[address] = keyId;
  }

  const auto path = walletMapPath();
  std::ofstream out(path);
  if (!out) {
    std::cerr << "⚠️ Failed to write wallet map at '" << path.string() << "'\n";
    return;
  }
  out << serialized.dump(2);
}

std::optional<std::string> findKeyIdInWalletMap(const std::string& canonicalLower) {
  std::lock_guard<std::mutex> lock(walletMapMutex());
  auto& map = loadWalletMapLocked();
  auto it = map.find(canonicalLower);
  if (it != map.end()) {
    return it->second;
  }
  return std::nullopt;
}

using EVPKeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;

std::string getOpenSslError() {
  unsigned long err = ERR_get_error();
  if (err == 0) {
    return "Unknown OpenSSL error";
  }
  char buffer[256];
  ERR_error_string_n(err, buffer, sizeof(buffer));
  return std::string(buffer);
}

EVPKeyPtr generateRsaKey(int bits) {
  ERR_clear_error();
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
  if (!ctx) {
    throw std::runtime_error("Failed to create EVP_PKEY_CTX for RSA keygen: " +
                             getOpenSslError());
  }

  if (EVP_PKEY_keygen_init(ctx) <= 0) {
    std::string err = getOpenSslError();
    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error("EVP_PKEY_keygen_init failed for RSA keygen: " + err);
  }

  if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
    std::string err = getOpenSslError();
    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error("Failed to set RSA key size: " + err);
  }

  EVP_PKEY* rawKey = nullptr;
  if (EVP_PKEY_keygen(ctx, &rawKey) <= 0) {
    std::string err = getOpenSslError();
    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error("EVP_PKEY_keygen failed for RSA key generation: " + err);
  }

  EVP_PKEY_CTX_free(ctx);
  return EVPKeyPtr(rawKey, &EVP_PKEY_free);
}

void writePrivateKeyPem(const fs::path& path, EVP_PKEY* key, const std::string& passphrase) {
  ERR_clear_error();
  std::unique_ptr<FILE, decltype(&::fclose)> file(::fopen(path.string().c_str(), "wb"), &::fclose);
  if (!file) {
    throw std::runtime_error("Failed to open private key file for writing: " + path.string());
  }

  const EVP_CIPHER* cipher = nullptr;
  unsigned char* passData = nullptr;
  int passLen = 0;

  std::string passCopy;
  if (!passphrase.empty()) {
    cipher = EVP_aes_256_cbc();
    passCopy = passphrase;
    passData = reinterpret_cast<unsigned char*>(passCopy.data());
    passLen = static_cast<int>(passCopy.size());
  }

  if (!PEM_write_PrivateKey(file.get(), key, cipher, passData, passLen, nullptr, nullptr)) {
    throw std::runtime_error("Failed to write RSA private key to " + path.string() +
                             ": " + getOpenSslError());
  }
}

void writePublicKeyPem(const fs::path& path, EVP_PKEY* key) {
  ERR_clear_error();
  std::unique_ptr<FILE, decltype(&::fclose)> file(::fopen(path.string().c_str(), "wb"), &::fclose);
  if (!file) {
    throw std::runtime_error("Failed to open public key file for writing: " + path.string());
  }

  if (!PEM_write_PUBKEY(file.get(), key)) {
    throw std::runtime_error("Failed to write RSA public key to " + path.string() +
                             ": " + getOpenSslError());
  }
}

std::optional<std::string> findKeyIdByCanonical(const std::string& canonicalLower) {
  const fs::path baseDir = DBPaths::getKeyDir();
  if (!fs::exists(baseDir)) {
    return std::nullopt;
  }

  const std::string dilSuffix = "_dilithium.pub";
  const std::string falSuffix = "_falcon.pub";

  for (const auto& entry : fs::directory_iterator(baseDir)) {
    if (!entry.is_regular_file()) continue;
    const auto filename = entry.path().filename().string();

    std::string prefix;
    if (endsWith(filename, dilSuffix)) {
      prefix = filename.substr(0, filename.size() - dilSuffix.size());
    } else if (endsWith(filename, falSuffix)) {
      prefix = filename.substr(0, filename.size() - falSuffix.size());
    } else {
      continue;
    }

    std::ifstream pub(entry.path(), std::ios::binary);
    if (!pub) continue;

    std::vector<unsigned char> buffer((std::istreambuf_iterator<char>(pub)),
                                      std::istreambuf_iterator<char>());
    if (buffer.empty()) continue;

    std::string derived = toLowerCopy(Crypto::deriveAddressFromPub(buffer));
    if (derived == canonicalLower) {
      return toLowerCopy(prefix);
    }
  }

  return std::nullopt;
}

std::optional<std::string> resolveKeyIdInternal(const std::string& addressOrKeyId) {
  if (addressOrKeyId.empty()) {
    return std::nullopt;
  }

  const std::string canonicalLower = toLowerCopy(addressOrKeyId);

  if (auto cached = getCachedResolvedKeyId(canonicalLower)) {
    return cached;
  }

  const fs::path baseDir = DBPaths::getKeyDir();
  auto hasDirectFiles = [&](const std::string& prefix) {
    return fs::exists(baseDir / (prefix + "_private.pem")) ||
           fs::exists(baseDir / (prefix + "_dilithium.key")) ||
           fs::exists(baseDir / (prefix + "_falcon.key"));
  };

  if (hasDirectFiles(canonicalLower)) {
    setCachedResolvedKeyId(canonicalLower, canonicalLower);
    return canonicalLower;
  }

  if (auto mapped = findKeyIdInWalletMap(canonicalLower)) {
    setCachedResolvedKeyId(canonicalLower, *mapped);
    return mapped;
  }

  if (auto matched = findKeyIdByCanonical(canonicalLower)) {
    Crypto::rememberWalletKeyIdentifier(canonicalLower, *matched);
    setCachedResolvedKeyId(canonicalLower, *matched);
    return matched;
  }

  return std::nullopt;
}

} // namespace

std::optional<std::string>
resolveWalletKeyIdentifier(const std::string& addressOrKeyId) {
  return resolveKeyIdInternal(addressOrKeyId);
}

void rememberWalletKeyIdentifier(const std::string& address,
                                 const std::string& keyId) {
  if (address.empty() || keyId.empty()) {
    return;
  }

  const std::string canonicalAddress = toLowerCopy(address);
  const std::string canonicalKeyId = toLowerCopy(keyId);

  {
    std::lock_guard<std::mutex> lock(walletMapMutex());
    auto& map = loadWalletMapLocked();
    map[canonicalAddress] = canonicalKeyId;
    persistWalletMapLocked(map);
  }

  setCachedResolvedKeyId(canonicalAddress, canonicalKeyId);
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
    keypair.publicKeyHex = Crypto::toHex(keypair.publicKey);
    keypair.privateKeyHex = Crypto::toHex(keypair.privateKey);

    std::string pubPath = KEY_DIR + username + "_dilithium.pub";
    std::string privPath = KEY_DIR + username + "_dilithium.key";

    // Clear any previous data
    std::ofstream(pubPath).close();
    std::ofstream(privPath).close();

    std::ofstream pub(pubPath, std::ios::binary);
    std::ofstream priv(privPath, std::ios::binary);

    pub.write(reinterpret_cast<char *>(pk), sizeof(pk));
    priv.write(reinterpret_cast<char *>(sk), sizeof(sk));

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
    keypair.publicKeyHex = Crypto::toHex(keypair.publicKey);
    keypair.privateKeyHex = Crypto::toHex(keypair.privateKey);

    std::string pubPath = KEY_DIR + username + "_falcon.pub";
    std::string privPath = KEY_DIR + username + "_falcon.key";

    // Clear any previous data
    std::ofstream(pubPath).close();
    std::ofstream(privPath).close();

    std::ofstream pub(pubPath, std::ios::binary);
    std::ofstream priv(privPath, std::ios::binary);

    pub.write(reinterpret_cast<char *>(pk), sizeof(pk));
    priv.write(reinterpret_cast<char *>(sk), sizeof(sk));

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
  std::cout << "[DEBUG] 🔏 Starting Dilithium signing..." << std::endl;
  std::cout << "[DEBUG] Message size: " << message.size() << " bytes" << std::endl;
  std::cout << "[DEBUG] Private key size: " << privKey.size() << " bytes" << std::endl;

  if (privKey.size() != CRYPTO_SECRETKEYBYTES) {
    std::cerr << "[ERROR] signWithDilithium() - Private key size mismatch! Expected: "
              << CRYPTO_SECRETKEYBYTES << " bytes\n";
    return {};
  }

  std::vector<unsigned char> signature(2700);  // Safe upper bound
  size_t siglen = 0;

  int ret = crypto_sign_signature(
      signature.data(), &siglen,
      message.data(), message.size(),
      nullptr, 0,
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
  std::cout << "✅ [DEBUG] Dilithium signature generated. Length: " << siglen << " bytes\n";
  return signature;
}

// --- Dilithium Verification ---
bool verifyWithDilithium(const std::vector<unsigned char> &message,
                         const std::vector<unsigned char> &signature,
                         const std::vector<unsigned char> &publicKey) {
  std::cout << "[DEBUG] 🔍 Verifying Dilithium signature..." << std::endl;
  std::cout << "[DEBUG] Message size: " << message.size() << " bytes" << std::endl;
  std::cout << "[DEBUG] Signature size: " << signature.size() << " bytes" << std::endl;
  std::cout << "[DEBUG] Public key size: " << publicKey.size() << " bytes" << std::endl;

  if (signature.empty() || message.empty() || publicKey.empty()) {
    std::cerr << "❌ [ERROR] One or more inputs are empty.\n";
    return false;
  }

  if (publicKey.size() != CRYPTO_PUBLICKEYBYTES) {
    std::cerr << "❌ [ERROR] Public key size mismatch! Expected: "
              << CRYPTO_PUBLICKEYBYTES << ", Got: " << publicKey.size() << "\n";
    return false;
  }

  int result = crypto_sign_verify(signature.data(), signature.size(),
                                  message.data(), message.size(),
                                  nullptr, 0, publicKey.data());

  if (result == 0) {
    std::cout << "✅ [DEBUG] Dilithium signature verified successfully.\n";
    return true;
  } else {
    std::cerr << "❌ [ERROR] Dilithium signature verification failed!\n";
    return false;
  }
}
// --- Falcon Signing ---
std::vector<unsigned char>
signWithFalcon(const std::vector<unsigned char> &message,
               const std::vector<unsigned char> &privKey) {
    const size_t expectedPrivSize = PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES;

    std::cout << "[DEBUG] Falcon Signing Initiated\n";
    std::cout << "  - Private Key Size: " << privKey.size() << " (Expected: " << expectedPrivSize << ")\n";
    std::cout << "  - Message Size    : " << message.size() << " (Expected: 32)\n";

    if (privKey.size() != expectedPrivSize) {
        std::cerr << "[ERROR] signWithFalcon() - Private key size mismatch!\n";
        return {};
    }

    if (message.size() != 32) {
        std::cerr << "[ERROR] signWithFalcon() - Message hash size invalid: " << message.size() << " (expected 32)\n";
        return {};
    }

    size_t maxSigLen = 1330;
    std::vector<unsigned char> signature(maxSigLen);
    size_t actualSigLen = 0;

    try {
        std::cout << "[DEBUG] Calling Falcon crypto_sign_signature()...\n";
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
    std::cout << "[DEBUG] Falcon Verification Initiated\n";
    std::cout << "  - Message Size   : " << message.size() << "\n";
    std::cout << "  - Signature Size : " << signature.size() << "\n";
    std::cout << "  - PublicKey Size : " << publicKey.size() << " (Expected: " 
              << PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES << ")\n";

    if (signature.empty() || message.empty() || publicKey.empty()) {
        std::cerr << "❌ [ERROR] Empty input to Falcon verification!\n";
        return false;
    }

    if (publicKey.size() != PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES) {
        std::cerr << "❌ [ERROR] Falcon public key size mismatch!\n";
        return false;
    }

    int result = PQCLEAN_FALCON1024_CLEAN_crypto_sign_verify(
        signature.data(), signature.size(),
        message.data(), message.size(),
        publicKey.data());

    if (result == 0) {
        std::cout << "✅ [DEBUG] Falcon signature verification PASSED\n";
        return true;
    } else {
        std::cerr << "❌ [DEBUG] Falcon signature verification FAILED! Return code: " << result << "\n";
        return false;
    }
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
  std::string resolved =
      resolveWalletKeyIdentifier(username).value_or(username);
  std::string pubPath = KEY_DIR + resolved + "_falcon.pub";
  if (!Crypto::fileExists(pubPath))
    return "";
  std::ifstream pubFile(pubPath, std::ios::binary);
  std::stringstream buffer;
  buffer << pubFile.rdbuf();
  return buffer.str();
}
// --- Public Key Loaders ---
std::vector<unsigned char> getPublicKeyDilithium(const std::string &walletAddress) {
  std::string resolved =
      Crypto::resolveWalletKeyIdentifier(walletAddress).value_or(walletAddress);
  std::string pubPath = KEY_DIR + resolved + "_dilithium.pub";
  std::ifstream pubFile(pubPath, std::ios::binary);
  if (!pubFile) return {};

  std::vector<unsigned char> buffer((std::istreambuf_iterator<char>(pubFile)),
                                    std::istreambuf_iterator<char>());
  if (buffer.size() != CRYPTO_PUBLICKEYBYTES) {
    std::cerr << "❌ [ERROR] Loaded Dilithium public key is incorrect length: " << buffer.size() << " (expected " << CRYPTO_PUBLICKEYBYTES << ")\n";
    return {};
  }
  return buffer;
}

std::vector<unsigned char> getPublicKeyFalcon(const std::string &walletAddress) {
  std::string resolved =
      Crypto::resolveWalletKeyIdentifier(walletAddress).value_or(walletAddress);
  std::string pubPath = KEY_DIR + resolved + "_falcon.pub";
  std::ifstream pubFile(pubPath, std::ios::binary);
  if (!pubFile) return {};

  std::vector<unsigned char> buffer((std::istreambuf_iterator<char>(pubFile)),
                                    std::istreambuf_iterator<char>());
  if (buffer.size() != PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES) {
    std::cerr << "❌ [ERROR] Loaded Falcon public key is incorrect length: " << buffer.size() << " (expected " << PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES << ")\n";
    return {};
  }
  return buffer;
}

// --- Key Loading ---
DilithiumKeyPair loadDilithiumKeys(const std::string &username) {
  DilithiumKeyPair keypair;

  std::string resolved =
      resolveWalletKeyIdentifier(username).value_or(username);

  std::string privPath = KEY_DIR + resolved + "_dilithium.key";
  std::string pubPath  = KEY_DIR + resolved + "_dilithium.pub";

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
      keypair.publicKeyHex = Crypto::toHex(pubBytes);
      keypair.privateKeyHex = Crypto::toHex(privBytes);
    }
  }

  return keypair;
}

FalconKeyPair loadFalconKeys(const std::string &username) {
  FalconKeyPair keypair;
  std::string resolved =
      resolveWalletKeyIdentifier(username).value_or(username);
  std::string privPath = KEY_DIR + resolved + "_falcon.key";
  std::string pubPath = KEY_DIR + resolved + "_falcon.pub";

  std::ifstream pub(pubPath, std::ios::binary);
  std::ifstream priv(privPath, std::ios::binary);

  if (pub && priv) {
    std::vector<unsigned char> pubBytes((std::istreambuf_iterator<char>(pub)),
                                        std::istreambuf_iterator<char>());
    std::vector<unsigned char> privBytes((std::istreambuf_iterator<char>(priv)),
                                         std::istreambuf_iterator<char>());

    if (pubBytes.size() != PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES) {
      std::cerr << "❌ [loadFalconKeys] Public key length mismatch. Got: "
                << pubBytes.size() << ", Expected: "
                << PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES << "\n";
    }

    keypair.publicKey = pubBytes;
    keypair.privateKey = privBytes;
    keypair.publicKeyHex = Crypto::toHex(pubBytes);
    keypair.privateKeyHex = Crypto::toHex(privBytes);
  }

  return keypair;
}

//- wrapper--
bool generatePostQuantumKeys(const std::string &username) {
    std::cout << "[DEBUG] Checking and generating PQ keys (Dilithium + Falcon) for: " << username << "\n";

    std::string dilPrivPath = KEY_DIR + username + "_dilithium.key";
    std::string dilPubPath  = KEY_DIR + username + "_dilithium.pub";
    std::string falPrivPath = KEY_DIR + username + "_falcon.key";
    std::string falPubPath  = KEY_DIR + username + "_falcon.pub";

    bool dilExists = fs::exists(dilPrivPath) && fs::exists(dilPubPath);
    bool falExists = fs::exists(falPrivPath) && fs::exists(falPubPath);

    if (dilExists && falExists) {
        std::cout << "✅ [INFO] Post-quantum keys already exist for user: " << username << "\n";
        return true;
    }

    std::cout << "🔐 Generating missing post-quantum keys for: " << username << "\n";

    // Generate and save Dilithium keys
    DilithiumKeyPair dilKeys = Crypto::generateDilithiumKeys(username);
    FalconKeyPair falKeys = Crypto::generateFalconKeys(username);

    bool dilValid = !dilKeys.privateKey.empty() && !dilKeys.publicKey.empty();
    bool falValid = !falKeys.privateKey.empty() && !falKeys.publicKey.empty();

    if (dilValid && falValid) {
        std::cout << "✅ [INFO] Successfully generated post-quantum keys for: " << username << "\n";
        return true;
    } else {
        std::cerr << "❌ [ERROR] Failed to generate post-quantum keys for: " << username << "\n";
        return false;
    }
}

// buff conversion
void serializeKeysToProtobuf(const std::string &privateKeyPath, std::string &output) {
    alyncoin::CryptoKeysProto keyProto;

    // 🔐 Binary-safe read of private key
    std::ifstream privFile(privateKeyPath, std::ios::binary);
    if (privFile) {
        std::vector<char> buffer((std::istreambuf_iterator<char>(privFile)), {});
        if (buffer.empty()) {
            std::cerr << "❌ Error: Private key file is empty: " << privateKeyPath << "\n";
            return;
        }
        keyProto.set_private_key(std::string(buffer.begin(), buffer.end()));
        privFile.close();
    } else {
        std::cerr << "❌ Error: Cannot open private key file: " << privateKeyPath << "\n";
        return;
    }

    // 🔓 Infer and read public key
    std::string publicKeyPath = privateKeyPath;
    size_t pos = publicKeyPath.find(".key");
    if (pos != std::string::npos) {
        publicKeyPath.replace(pos, 4, ".pub");
    }

    std::ifstream pubFile(publicKeyPath, std::ios::binary);
    if (pubFile) {
        std::vector<char> buffer((std::istreambuf_iterator<char>(pubFile)), {});
        if (buffer.empty()) {
            std::cerr << "⚠️ Warning: Public key file is empty: " << publicKeyPath << "\n";
        } else {
            keyProto.set_public_key(std::string(buffer.begin(), buffer.end()));
        }
        pubFile.close();
    } else {
        std::cerr << "⚠️ Warning: Cannot open public key file: " << publicKeyPath << "\n";
    }

    if (!keyProto.SerializeToString(&output)) {
        std::cerr << "❌ Error: Failed to serialize CryptoKeysProto to string!\n";
    }
}

bool deserializeKeysFromProtobuf(const std::string &input,
                                  std::vector<unsigned char> &privateKey,
                                  std::vector<unsigned char> &publicKey) {
    alyncoin::CryptoKeysProto keyProto;
    if (!keyProto.ParseFromString(input)) {
        std::cerr << "❌ Error: Failed to parse Protobuf key data!\n";
        return false;
    }

    const std::string &privStr = keyProto.private_key();
    const std::string &pubStr  = keyProto.public_key();

    if (privStr.empty()) {
        std::cerr << "❌ Error: Parsed private key is empty.\n";
        return false;
    }

    privateKey.assign(privStr.begin(), privStr.end());
    publicKey.assign(pubStr.begin(), pubStr.end());

    std::cout << "✅ [DEBUG] Deserialized Private Key Length: " << privateKey.size() << "\n";
    std::cout << "✅ [DEBUG] Deserialized Public Key Length: "  << publicKey.size() << "\n";

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

  std::cout << "✅ [DEBUG] toHex() - Converted " << data.size()
            << " bytes to hex string of length " << hex.length() << "\n";

  return hex;
}

// Convert hex string back to bytes
std::vector<unsigned char> fromHex(const std::string &hex) {
    std::vector<unsigned char> bytes;

    if (hex.empty()) {
        std::cerr << "❌ [fromHex] Input is empty.\n";
        return {};
    }

    if (hex.length() % 2 != 0) {
        std::cerr << "❌ [fromHex] Hex string has odd length: " << hex.length() << "\n";
        return {};
    }

    // Upper safe limit to avoid oversized allocations
    const size_t MAX_HEX_LENGTH = 1000000;  // 1MB of hex = 500KB binary
    if (hex.length() > MAX_HEX_LENGTH) {
        std::cerr << "❌ [fromHex] Hex string too long (" << hex.length() << " chars). Skipping parse.\n";
        return {};
    }

    bytes.reserve(hex.length() / 2);

    auto hexToNibble = [](char c) -> int {
        if ('0' <= c && c <= '9') return c - '0';
        if ('a' <= c && c <= 'f') return c - 'a' + 10;
        if ('A' <= c && c <= 'F') return c - 'A' + 10;
        return -1;
    };

    for (size_t i = 0; i < hex.length(); i += 2) {
        char high = hex[i];
        char low  = hex[i + 1];

        int highVal = hexToNibble(high);
        int lowVal  = hexToNibble(low);

        if (highVal == -1 || lowVal == -1) {
            std::cerr << "❌ [fromHex] Invalid hex characters: '" << high << "' or '" << low
                      << "' at position " << i << "\n";
            return {};
        }

        bytes.push_back(static_cast<unsigned char>((highVal << 4) | lowVal));
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
    std::error_code ec;
    fs::create_directories(KEY_DIR, ec);
    if (ec) {
      std::cerr << "⚠️ Failed to create key directory '" << KEY_DIR
                << "': " << ec.message() << "\n";
    }
  }
}
// ✅ Generate Private & Public Key Pair for a User (with Debugging)
void generateKeysForUser(const std::string &username) {
  std::cout << "[DEBUG] Ensuring keys directory exists..." << std::endl;
  ensureKeysDirectory();

  std::string cleanUsername = username;
  std::replace(cleanUsername.begin(), cleanUsername.end(), ' ', '_');

  fs::path baseDir(KEY_DIR);
  fs::path privateKeyPath = baseDir / (cleanUsername + "_private.pem");
  fs::path publicKeyPath = baseDir / (cleanUsername + "_public.pem");

  std::cout << "[DEBUG] Private key path: " << privateKeyPath << std::endl;
  std::cout << "[DEBUG] Public key path: " << publicKeyPath << std::endl;

  if (fs::exists(privateKeyPath) && fs::exists(publicKeyPath)) {
    std::cout << "🔑 Keys for user " << cleanUsername
              << " already exist. Skipping generation.\n";
    return;
  }

  std::cout << "🔑 Generating new keys for user: " << cleanUsername << "\n";

  auto rsaKey = generateRsaKey(2048);
  std::cout << "[DEBUG] RSA key pair generated in memory." << std::endl;

  writePrivateKeyPem(privateKeyPath, rsaKey.get(), "");
  std::cout << "[DEBUG] Private key written to " << privateKeyPath << std::endl;

  writePublicKeyPem(publicKeyPath, rsaKey.get());
  std::cout << "[DEBUG] Public key written to " << publicKeyPath << std::endl;

  // Final check to ensure both files now exist
  if (fs::exists(privateKeyPath) && fs::exists(publicKeyPath)) {
    std::cout << "✅ [INFO] Successfully generated keys for user: "
              << cleanUsername << std::endl;
  } else {
    throw std::runtime_error("Key files missing after generation attempt for "
                             "user '" +
                             cleanUsername + "'");
  }
}

// 🔐 Generate RSA key pair protected with a passphrase
void generateKeysForUser(const std::string &username,
                         const std::string &passphrase) {
  std::cout << "[DEBUG] Ensuring keys directory exists..." << std::endl;
  ensureKeysDirectory();

  std::string cleanUsername = username;
  std::replace(cleanUsername.begin(), cleanUsername.end(), ' ', '_');

  fs::path baseDir(KEY_DIR);
  fs::path privateKeyPath = baseDir / (cleanUsername + "_private.pem");
  fs::path publicKeyPath = baseDir / (cleanUsername + "_public.pem");

  if (fs::exists(privateKeyPath) && fs::exists(publicKeyPath)) {
    std::cout << "🔑 Keys for user " << cleanUsername
              << " already exist. Skipping generation.\n";
    return;
  }

  std::cout << "🔑 Generating new keys for user: " << cleanUsername << "\n";

  auto rsaKey = generateRsaKey(2048);
  std::cout << "[DEBUG] RSA key pair generated in memory." << std::endl;

  writePrivateKeyPem(privateKeyPath, rsaKey.get(), passphrase);
  std::cout << "[DEBUG] Encrypted private key written to " << privateKeyPath
            << std::endl;

  writePublicKeyPem(publicKeyPath, rsaKey.get());
  std::cout << "[DEBUG] Public key written to " << publicKeyPath << std::endl;

  if (fs::exists(privateKeyPath) && fs::exists(publicKeyPath)) {
    std::cout << "✅ [INFO] Successfully generated keys for user: "
              << cleanUsername << std::endl;
  } else {
    throw std::runtime_error("Key files missing after generation attempt for "
                             "user '" +
                             cleanUsername + "'");
  }
}

// 🔓 Load an encrypted private key and return PEM string
std::string loadPrivateKeyDecrypted(const std::string &path,
                                    const std::string &passphrase) {
  FILE *fp = fopen(path.c_str(), "rb");
  if (!fp)
    throw std::runtime_error("❌ Failed to open private key: " + path);

  EVP_PKEY *pkey =
      PEM_read_PrivateKey(fp, nullptr, nullptr, (void *)passphrase.c_str());
  fclose(fp);
  if (!pkey)
    throw std::runtime_error("❌ Failed to read private key with passphrase");

  BIO *mem = BIO_new(BIO_s_mem());
  if (!PEM_write_bio_PrivateKey(mem, pkey, nullptr, nullptr, 0, nullptr,
                                nullptr)) {
    BIO_free(mem);
    EVP_PKEY_free(pkey);
    throw std::runtime_error("❌ Failed to write key to memory");
  }

  BUF_MEM *ptr;
  BIO_get_mem_ptr(mem, &ptr);
  std::string out(ptr->data, ptr->length);
  BIO_free(mem);
  EVP_PKEY_free(pkey);
  return out;
}

// ✅ Generate Private Key (Auto-Creation)
std::string generatePrivateKey(const std::string &user,
                               const std::string &passphrase) {
  ensureKeysDirectory();

  const fs::path privateKeyPath = fs::path(DBPaths::getKeyDir())
                                  / (user + "_private.pem");
  const fs::path publicKeyPath = fs::path(DBPaths::getKeyDir())
                                 / (user + "_public.pem");

  auto readFileToString = [](const fs::path &path) {
    std::ifstream in(path, std::ios::binary);
    std::stringstream buffer;
    buffer << in.rdbuf();
    return buffer.str();
  };

  if (fs::exists(privateKeyPath)) {
    // Ensure a matching public key exists; if it doesn't, try to derive it
    if (!fs::exists(publicKeyPath)) {
      try {
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(
            loadPrivateKey(privateKeyPath.string()), &EVP_PKEY_free);
        if (key) {
          writePublicKeyPem(publicKeyPath, key.get());
        }
      } catch (const std::exception &e) {
        std::cerr << "⚠️ Failed to regenerate public key for '" << user
                  << "': " << e.what() << "\n";
      }
    }
    return readFileToString(privateKeyPath);
  }

  auto rsaKey = generateRsaKey(4096);

  std::string effectivePass = passphrase;
  if (effectivePass == "unused") {
    effectivePass.clear();
  }

  writePrivateKeyPem(privateKeyPath, rsaKey.get(), effectivePass);
  writePublicKeyPem(publicKeyPath, rsaKey.get());

  return readFileToString(privateKeyPath);
}

// ✅ Get Public Key from Private Key (Auto-Creation)
std::string getPublicKey(const std::string &user) {
  ensureKeysDirectory();
  const fs::path privateKeyPath = fs::path(getPrivateKeyPath(user));
  const fs::path publicKeyPath = fs::path(KEY_DIR) / (user + "_public.pem");

  auto readFileToString = [](const fs::path &path) {
    std::ifstream in(path, std::ios::binary);
    std::stringstream buffer;
    buffer << in.rdbuf();
    return buffer.str();
  };

  if (fs::exists(publicKeyPath)) {
    return readFileToString(publicKeyPath);
  }

  if (!fs::exists(privateKeyPath)) {
    std::cerr << "⚠️ [WARNING] Private key missing for " << user
              << ". Generating new key pair...\n";
    Crypto::generateKeysForUser(user);
  }

  if (!fs::exists(publicKeyPath)) {
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(
        loadPrivateKey(privateKeyPath.string()), &EVP_PKEY_free);
    if (!key) {
      std::cerr << "❌ [ERROR] Unable to load private key for '" << user
                << "' to derive public key.\n";
      return "";
    }
    try {
      writePublicKeyPem(publicKeyPath, key.get());
    } catch (const std::exception &e) {
      std::cerr << "❌ [ERROR] Failed to write public key for '" << user
                << "': " << e.what() << "\n";
      return "";
    }
  }

  if (!fs::exists(publicKeyPath)) {
    std::cerr << "❌ [ERROR] Public key generation failed for '" << user
              << "'.\n";
    return "";
  }

  return readFileToString(publicKeyPath);
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

bool keysExist(const std::string &username) {
    std::string resolved =
        resolveWalletKeyIdentifier(username).value_or(username);

    std::string rsaPriv = getPrivateKeyPath(resolved);
    std::string rsaPub  = getPublicKeyPath(resolved);
    std::string dilPriv = KEY_DIR + resolved + "_dilithium.key";
    std::string dilPub  = KEY_DIR + resolved + "_dilithium.pub";
    std::string falPriv = KEY_DIR + resolved + "_falcon.key";
    std::string falPub  = KEY_DIR + resolved + "_falcon.pub";

    return fileExists(rsaPriv) && fileExists(rsaPub) &&
           fileExists(dilPriv) && fileExists(dilPub) &&
           fileExists(falPriv) && fileExists(falPub);
}
// ✅ Ensure Miner Keys Exist (Auto-Handling)
void ensureMinerKeys() {
  ensureKeysDirectory();
  std::string minerPrivateKey = generatePrivateKey("miner", "defaultpass");
  std::string minerPublicKey = getPublicKey("miner");

  // Also generate Dilithium & Falcon keypairs if missing
  Crypto::generatePostQuantumKeys("miner");

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
std::string encodeRaw(const unsigned char* data, size_t len, bool wrap) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new(BIO_s_mem());
    if (!b64 || !mem) throw std::runtime_error("BIO_new failed");
    if (!wrap) BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, mem);
    BIO_write(b64, data, static_cast<int>(len));
    BIO_flush(b64);

    BUF_MEM* memPtr;
    BIO_get_mem_ptr(b64, &memPtr);
    std::string out(memPtr->data, memPtr->length);
    BIO_free_all(b64);
    return out;
}
std::string decodeRaw(const char* data, size_t len, bool wrapped) {
    std::cout << "[decodeRaw DEBUG] Input len: " << len
              << " | First chars: [" << std::string(data, std::min(len, size_t(60)))
              << "] | Last chars: [" << std::string(data + len - std::min(len, size_t(10)), std::min(len, size_t(10))) << "]\n";

    while (len > 0 && (data[len-1] == '\n' || data[len-1] == '\r'))
        --len;

    BIO* mem = BIO_new_mem_buf(data, static_cast<int>(len));
    BIO* b64 = BIO_new(BIO_f_base64());
    if (!mem || !b64) throw std::runtime_error("BIO_new failed");
    if (!wrapped) BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO* bio = BIO_push(b64, mem);

    std::vector<unsigned char> buffer(len);
    int n = BIO_read(bio, buffer.data(), static_cast<int>(buffer.size()));
    BIO_free_all(bio);

    if (n <= 0) {
        std::cerr << "[decodeRaw DEBUG] Decode failed, returned size = " << n << "\n";
        return "";
    }

    std::cout << "[decodeRaw DEBUG] Decoded size: " << n << "\n";
    return std::string(reinterpret_cast<char*>(buffer.data()), n);
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
  std::string resolved =
      Crypto::resolveWalletKeyIdentifier(walletAddress).value_or(walletAddress);
  std::string pubPath = KEY_DIR + resolved + "_dilithium.pub";
  if (!std::filesystem::exists(pubPath)) {
    pubPath = KEY_DIR + resolved + "_falcon.pub";
  }

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

  std::vector<unsigned char> privKeyData;

  try {
    if (isFilePath) {
      if (!fs::exists(privateKeyPath)) {
        std::cerr << "❌ [ERROR] Private key file not found: " << privateKeyPath << std::endl;
        return "";
      }
      std::ifstream file(privateKeyPath, std::ios::binary);
      privKeyData = std::vector<unsigned char>((std::istreambuf_iterator<char>(file)),
                                               std::istreambuf_iterator<char>());
    } else {
      privKeyData = std::vector<unsigned char>(privateKeyPath.begin(), privateKeyPath.end());
    }

    if (privKeyData.empty()) {
      std::cerr << "❌ [ERROR] Private key is empty!\n";
      return "";
    }

    std::vector<unsigned char> messageBytes(message.begin(), message.end());

    if (privateKeyPath.find("falcon") != std::string::npos) {
      auto sig = Crypto::signWithFalcon(messageBytes, privKeyData);
      return Crypto::toHex(sig);
    } else if (privateKeyPath.find("dilithium") != std::string::npos) {
      auto sig = Crypto::signWithDilithium(messageBytes, privKeyData);
      return Crypto::toHex(sig);
    } else {
      // Assume RSA PEM
      BIO *bio = BIO_new_mem_buf(privKeyData.data(), privKeyData.size());
      EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
      BIO_free(bio);

      if (!pkey) {
        std::cerr << "❌ [ERROR] Failed to parse private RSA key.\n";
        return "";
      }

      EVP_MD_CTX *ctx = EVP_MD_CTX_new();
      if (!ctx) {
        EVP_PKEY_free(pkey);
        std::cerr << "❌ [ERROR] Failed to create EVP context.\n";
        return "";
      }

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
  } catch (const std::exception &ex) {
    std::cerr << "❌ [ERROR] signMessage threw exception: " << ex.what() << "\n";
    return "";
  }
}

// ✅ Verify a signed message using public key (RSA/Falcon/Dilithium)
bool verifyMessage(const std::string &publicKeyPath,
                   const std::string &signature, const std::string &message) {
  if (!fs::exists(publicKeyPath)) {
    std::cerr << "❌ [ERROR] Public key file not found: " << publicKeyPath << std::endl;
    return false;
  }

  std::ifstream pubFile(publicKeyPath, std::ios::binary);
  std::vector<unsigned char> pubKeyData((std::istreambuf_iterator<char>(pubFile)),
                                        std::istreambuf_iterator<char>());

  std::vector<unsigned char> msgBytes(message.begin(), message.end());

  try {
    if (publicKeyPath.find("falcon") != std::string::npos) {
      std::vector<unsigned char> sigBytes = Crypto::fromHex(signature);
      return Crypto::verifyWithFalcon(msgBytes, sigBytes, pubKeyData);
    } else if (publicKeyPath.find("dilithium") != std::string::npos) {
      std::vector<unsigned char> sigBytes = Crypto::fromHex(signature);
      return Crypto::verifyWithDilithium(msgBytes, sigBytes, pubKeyData);
    } else {
      std::string decodedSignature = base64Decode(signature);
      BIO *bio = BIO_new_mem_buf(pubKeyData.data(), pubKeyData.size());
      EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
      BIO_free(bio);

      if (!pkey) {
        std::cerr << "❌ [ERROR] Failed to parse RSA public key.\n";
        return false;
      }

      EVP_MD_CTX *ctx = EVP_MD_CTX_new();
      if (!ctx) {
        EVP_PKEY_free(pkey);
        std::cerr << "❌ [ERROR] Failed to create EVP context.\n";
        return false;
      }

      EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pkey);
      EVP_DigestVerifyUpdate(ctx, message.c_str(), message.size());

      bool result = EVP_DigestVerifyFinal(ctx, (unsigned char *)decodedSignature.data(),
                                          decodedSignature.size()) == 1;

      EVP_MD_CTX_free(ctx);
      EVP_PKEY_free(pkey);

      return result;
    }
  } catch (const std::exception &ex) {
    std::cerr << "❌ [ERROR] verifyMessage threw exception: " << ex.what() << "\n";
    return false;
  }
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

//
std::string blake3Hash(const std::string &input) {
    uint8_t output[BLAKE3_OUT_LEN];
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, input.data(), input.size());
    blake3_hasher_finalize(&hasher, output, BLAKE3_OUT_LEN);

    // 🛠 Correct way: return output as clean std::string (32 bytes)
    return std::string(reinterpret_cast<const char *>(output), BLAKE3_OUT_LEN);
}

//
std::vector<unsigned char> sha256ToBytes(const std::string &input) {
    std::string hashHex = sha256(input);
    return fromHex(hashHex);
}

bool isLikelyHex(const std::string& str) {
    if (str.empty()) return false;
    if (str.size() % 2 != 0) return false;

    for (char c : str) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) {
            return false;
        }
    }
    return true;
}

// 🚀 Safer Hex Decoder (quiet failure, no std::cerr flood unless you want)
std::optional<std::vector<unsigned char>> safeFromHex(const std::string& hex, const std::string& context) {
    if (hex.empty()) {
        std::cerr << "❌ [safeFromHex] [" << context << "] Empty input.\n";
        return std::nullopt;
    }

    if (hex.size() % 2 != 0) {
        std::cerr << "❌ [safeFromHex] [" << context << "] Odd-length hex string: " << hex.size() << "\n";
        return std::nullopt;
    }

    const size_t MAX_SAFE_LENGTH = 1000000; // 1 MB of hex chars
    if (hex.size() > MAX_SAFE_LENGTH) {
        std::cerr << "❌ [safeFromHex] [" << context << "] Hex string too long: " << hex.size() << " chars.\n";
        return std::nullopt;
    }

    std::vector<unsigned char> bytes;
    bytes.reserve(hex.size() / 2);

    auto hexToNibble = [](unsigned char c) -> int {
        if ('0' <= c && c <= '9') return c - '0';
        if ('a' <= c && c <= 'f') return c - 'a' + 10;
        if ('A' <= c && c <= 'F') return c - 'A' + 10;
        return -1;
    };

    for (size_t i = 0; i < hex.size(); i += 2) {
        int high = hexToNibble(static_cast<unsigned char>(hex[i]));
        int low  = hexToNibble(static_cast<unsigned char>(hex[i + 1]));
        if (high == -1 || low == -1) {
            std::cerr << "❌ [safeFromHex] [" << context << "] Invalid hex character at pos " << i << ": '" << hex[i] << "' or '" << hex[i+1] << "'\n";
            return std::nullopt;
        }
        bytes.push_back(static_cast<unsigned char>((high << 4) | low));
    }

    return bytes;
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

std::string Crypto::base64Encode(const std::string& input, bool wrapLines) {
    return encodeRaw(reinterpret_cast<const unsigned char*>(input.data()), input.size(), wrapLines);
}
std::string Crypto::base64Decode(const std::string& input, bool inputIsWrapped) {
    return decodeRaw(input.data(), input.size(), inputIsWrapped);
}
