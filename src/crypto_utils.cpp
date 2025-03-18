#include "crypto_utils.h"
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <filesystem>
#include <iostream>
#include <vector>
#include <sstream>
#include <iomanip>
#include <fstream>
#include "blake3.h"
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <thread>
#include <chrono>
#include <unistd.h>
#include <fcntl.h>
#include "generated/crypto_protos.pb.h"
#include <filesystem>

namespace fs = std::filesystem;

namespace Crypto {

// ✅ SHA-256 Implementation
std::string sha256(const std::string& input) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    const EVP_MD* md = EVP_sha256();
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
std::string keccak256(const std::string& input) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    const EVP_MD* md = EVP_get_digestbyname("SHA3-256");  // Changed here
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
std::string blake3(const std::string& input) {
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
std::string hybridHash(const std::string& input) {
    return keccak256(blake3(input));
}
// ✅ Generate Address Using Hybrid Hash
std::string generateAddress(const std::string& publicKey) {
    return hybridHash(publicKey).substr(0, 40);
}

//buff conversion
void serializeKeysToProtobuf(const std::string& privateKeyPath, std::string& output) {
    alyncoin::CryptoKeysProto keyProto;

    std::ifstream privFile(privateKeyPath);
    if (privFile) {
        std::stringstream buffer;
        buffer << privFile.rdbuf();
         keyProto.set_private_key(buffer.str());
        privFile.close();
    } else {
        std::cerr << "❌ Error: Cannot open private key file: " << privateKeyPath << std::endl;
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
        std::cerr << "⚠️ Warning: Cannot open public key file: " << publicKeyPath << std::endl;
    }

    keyProto.SerializeToString(&output);
}

bool deserializeKeysFromProtobuf(const std::string& input, std::string& privateKey, std::string& publicKey) {
    alyncoin::CryptoKeysProto keyProto;
    if (!keyProto.ParseFromString(input)) {
        std::cerr << "❌ Error: Failed to parse Protobuf key data!" << std::endl;
        return false;
    }

    privateKey = keyProto.private_key();
    publicKey = keyProto.public_key();
    return true;
}


// ✅ Ensure "keys" directory exists
void ensureKeysDirectory() {
    if (!fs::exists(KEY_DIR)) {
        fs::create_directories(KEY_DIR);
    }
}
// ✅ Define key storage directory explicitly
const std::string KEY_DIR = "/root/.alyncoin/keys/";

// ✅ Generate Private & Public Key Pair for a User (with Debugging)
void generateKeysForUser(const std::string& username) {
    std::cout << "[DEBUG] Ensuring keys directory exists..." << std::endl;
    ensureKeysDirectory();

    std::string cleanUsername = username;
    std::replace(cleanUsername.begin(), cleanUsername.end(), ' ', '_');

    std::string privateKeyPath = KEY_DIR + cleanUsername + "_private.pem";
    std::string publicKeyPath = KEY_DIR + cleanUsername + "_public.pem";

    std::cout << "[DEBUG] Private key path: " << privateKeyPath << std::endl;
    std::cout << "[DEBUG] Public key path: " << publicKeyPath << std::endl;

    if (fs::exists(privateKeyPath) && fs::exists(publicKeyPath)) {
        std::cout << "🔑 Keys for user " << cleanUsername << " already exist. Skipping generation.\n";
        return;
    }

    std::cout << "🔑 Generating new keys for user: " << cleanUsername << "\n";

    std::string privCmd = "openssl genpkey -algorithm RSA -out \"" + privateKeyPath + "\" -pkeyopt rsa_keygen_bits:2048";
    std::string pubCmd = "openssl rsa -in \"" + privateKeyPath + "\" -pubout -out \"" + publicKeyPath + "\"";

    std::cout << "[DEBUG] Running private key generation command: " << privCmd << std::endl;
    int privStatus = system(privCmd.c_str());
    if (privStatus != 0) {
        std::cerr << "❌ [ERROR] Private key generation failed for user: " << cleanUsername << std::endl;
        return;
    }
    std::cout << "[DEBUG] Private key generated successfully." << std::endl;

    std::cout << "[DEBUG] Running public key extraction command: " << pubCmd << std::endl;
    int pubStatus = system(pubCmd.c_str());
    if (pubStatus != 0) {
        std::cerr << "❌ [ERROR] Public key extraction failed for user: " << cleanUsername << std::endl;
        return;
    }
    std::cout << "[DEBUG] Public key generated successfully." << std::endl;

    // Final check to ensure both files now exist
    if (fs::exists(privateKeyPath) && fs::exists(publicKeyPath)) {
        std::cout << "✅ [INFO] Successfully generated keys for user: " << cleanUsername << std::endl;
    } else {
        std::cerr << "❌ [ERROR] Key files missing after generation attempt!" << std::endl;
    }
}


// ✅ Generate Private Key (Auto-Creation)
std::string generatePrivateKey(const std::string& user, const std::string& passphrase) {
    ensureKeysDirectory();
    const std::string keyDir = "keys/";
    const std::string privateKeyPath = keyDir + user + "_private.pem";

    // If the private key already exists, read and return its contents
    if (fs::exists(privateKeyPath)) {
        std::ifstream privFile(privateKeyPath);
        std::stringstream buffer;
        buffer << privFile.rdbuf();
        return buffer.str();
    }

    // Create a new RSA key
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) {
        std::cerr << "❌ Error: Failed to create EVP_PKEY_CTX." << std::endl;
        return "";
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 4096) <= 0) {
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

    // Write the private key to a PEM file, encrypted with the provided passphrase
    BIO* bio = BIO_new_file(privateKeyPath.c_str(), "w");
    if (!bio) {
        std::cerr << "❌ Error: Failed to create file BIO." << std::endl;
        EVP_PKEY_free(pkey);
        return "";
    }

    const EVP_CIPHER* cipher = EVP_aes_256_cbc();
    if (!PEM_write_bio_PrivateKey(bio, pkey, cipher, nullptr, 0, nullptr, (void*)passphrase.c_str())) {
        std::cerr << "❌ Error: Failed to write private key to file with encryption." << std::endl;
        BIO_free(bio);
        EVP_PKEY_free(pkey);
        return "";
    }
    BIO_free(bio);

    // Convert the private key to a string
    bio = BIO_new(BIO_s_mem());
    if (!bio) {
        std::cerr << "❌ Error: Failed to create memory BIO." << std::endl;
        EVP_PKEY_free(pkey);
        return "";
    }

    if (!PEM_write_bio_PrivateKey(bio, pkey, cipher, nullptr, 0, nullptr, (void*)passphrase.c_str())) {
        std::cerr << "❌ Error: Failed to write private key to memory with encryption." << std::endl;
        BIO_free(bio);
        EVP_PKEY_free(pkey);
        return "";
    }

    char* keyData;
    long keySize = BIO_get_mem_data(bio, &keyData);
    std::string privateKey(keyData, keySize);

    EVP_PKEY_free(pkey);
    BIO_free(bio);

    return privateKey;
}
// ✅ Get Public Key from Private Key (Auto-Creation)
std::string getPublicKey(const std::string& user) {
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
        std::cerr << "⚠️ [WARNING] Private key missing for " << user << ". Generating new key pair...\n";
        Crypto::generateKeysForUser(user);
    }

    // ✅ Generate Public Key from Private Key
    std::string cmd = "openssl rsa -in \"" + privateKeyPath + "\" -pubout -out \"" + publicKeyPath + "\"";
    if (system(cmd.c_str()) != 0) {
        std::cerr << "❌ [ERROR] Failed to generate public key for " << user << "!\n";
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
EVP_PKEY* loadPrivateKey(const std::string& privateKeyPath) {
    if (!fs::exists(privateKeyPath)) {
        std::cerr << "❌ [ERROR] Private key file missing: " << privateKeyPath << "\n";
        return nullptr;
    }

    FILE* fp = fopen(privateKeyPath.c_str(), "r");
    if (!fp) {
        std::cerr << "❌ [ERROR] Cannot open private key file: " << privateKeyPath << "\n";
        return nullptr;
    }

    EVP_PKEY* privateKey = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
    fclose(fp);

    if (!privateKey) {
        std::cerr << "❌ [ERROR] Failed to parse private key!\n";
    }
    return privateKey;
}

// ✅ Ensure Wallet Keys Exist for Any User (Auto-Handling)
void ensureUserKeys(const std::string& username) {
    ensureKeysDirectory();
    generateKeysForUser(username);
}
//
bool fileExists(const std::string& path) {
    return std::filesystem::exists(path);
}
// ✅ Ensure Miner Keys Exist (Auto-Handling)
void ensureMinerKeys() {
    ensureKeysDirectory();
    std::string minerPrivateKey = generatePrivateKey("miner");
    std::string minerPublicKey = getPublicKey("miner");

    if (minerPrivateKey.empty() || minerPublicKey.empty()) {
        std::cerr << "❌ Critical Error: Miner keys could not be generated!" << std::endl;
    } else {
        std::cout << "✅ Miner keys verified and exist.\n";
    }
}

// ✅ Generate Miner Address from Public Key
std::string generateMinerAddress() {
    std::string publicKey = getPublicKey("miner");
    if (publicKey.empty()) {
        std::cerr << "❌ Error: Cannot generate miner address. Public key missing!\n";
        return "";
    }
    return Crypto::generateAddress(publicKey);
}

// ✅ Base64 Encode
std::string base64Encode(const std::string& input) {
    BIO* bio, * b64;
    BUF_MEM* bufferPtr;

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
std::string base64Decode(const std::string& input) {
    BIO* bio, * b64;
    std::vector<char> buffer(input.size());

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(input.data(), input.size());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    int decodedSize = BIO_read(bio, buffer.data(), input.size());
    BIO_free_all(bio);

    if (decodedSize <= 0) return "";
    return std::string(buffer.data(), decodedSize);
}
//
bool encryptFile(const std::string& inputFilePath, const std::string& outputFilePath, const std::string& publicKeyPath) {
    // Read the public key
    FILE* pubKeyFile = fopen(publicKeyPath.c_str(), "rb");
    if (!pubKeyFile) {
        std::cerr << "Unable to open public key file: " << publicKeyPath << std::endl;
        return false;
    }

    RSA* rsaPublicKey = PEM_read_RSA_PUBKEY(pubKeyFile, nullptr, nullptr, nullptr);
    fclose(pubKeyFile);

    if (!rsaPublicKey) {
        std::cerr << "Error reading public key from file." << std::endl;
        return false;
    }

    // Read the input file
    std::ifstream inputFile(inputFilePath, std::ios::binary);
    if (!inputFile) {
        std::cerr << "Unable to open input file: " << inputFilePath << std::endl;
        RSA_free(rsaPublicKey);
        return false;
    }

    std::string inputData((std::istreambuf_iterator<char>(inputFile)), std::istreambuf_iterator<char>());
    inputFile.close();

    // Encrypt the data
    int rsaLen = RSA_size(rsaPublicKey);
    std::unique_ptr<unsigned char[]> encryptedData(new unsigned char[rsaLen]);

    int resultLen = RSA_public_encrypt(inputData.size(),
                                       reinterpret_cast<const unsigned char*>(inputData.c_str()),
                                       encryptedData.get(),
                                       rsaPublicKey,
                                       RSA_PKCS1_OAEP_PADDING);

    RSA_free(rsaPublicKey);

    if (resultLen == -1) {
        std::cerr << "Error during encryption." << std::endl;
        return false;
    }

    // Write the encrypted data to the output file
    std::ofstream outputFile(outputFilePath, std::ios::binary);
    if (!outputFile) {
        std::cerr << "Unable to open output file: " << outputFilePath << std::endl;
        return false;
    }

    outputFile.write(reinterpret_cast<const char*>(encryptedData.get()), resultLen);
    outputFile.close();

    return true;
}

//
bool decryptFile(const std::string& inputFilePath, const std::string& outputFilePath, const std::string& privateKeyPath) {
    // Read the private key
    FILE* privKeyFile = fopen(privateKeyPath.c_str(), "rb");
    if (!privKeyFile) {
        std::cerr << "Unable to open private key file: " << privateKeyPath << std::endl;
        return false;
    }

    RSA* rsaPrivateKey = PEM_read_RSAPrivateKey(privKeyFile, nullptr, nullptr, nullptr);
    fclose(privKeyFile);

    if (!rsaPrivateKey) {
        std::cerr << "Error reading private key from file." << std::endl;
        return false;
    }

    // Read the encrypted file
    std::ifstream inputFile(inputFilePath, std::ios::binary);
    if (!inputFile) {
        std::cerr << "Unable to open input file: " << inputFilePath << std::endl;
        RSA_free(rsaPrivateKey);
        return false;
    }

    std::string encryptedData((std::istreambuf_iterator<char>(inputFile)), std::istreambuf_iterator<char>());
    inputFile.close();

    // Decrypt the data
    int rsaLen = RSA_size(rsaPrivateKey);
    std::unique_ptr<unsigned char[]> decryptedData(new unsigned char[rsaLen]);

    int resultLen = RSA_private_decrypt(encryptedData.size(),
                                        reinterpret_cast<const unsigned char*>(encryptedData.c_str()),
                                        decryptedData.get(),
                                        rsaPrivateKey,
                                        RSA_PKCS1_OAEP_PADDING);

    RSA_free(rsaPrivateKey);

    if (resultLen == -1) {
        std::cerr << "Error during decryption." << std::endl;
        return false;
    }

    // Write the decrypted data to the output file
    std::ofstream outputFile(outputFilePath, std::ios::binary);
    if (!outputFile) {
        std::cerr << "Unable to open output file: " << outputFilePath << std::endl;
        return false;
    }

    outputFile.write(reinterpret_cast<const char*>(decryptedData.get()), resultLen);
    outputFile.close();

    return true;
}

//
std::string getPrivateKeyPath(const std::string& username, const std::string& baseDir) {
    ensureKeysDirectory();
    return baseDir + username + "_private.pem";
}
std::string getPublicKeyPath(const std::string& username, const std::string& baseDir) {
    ensureKeysDirectory();
    return baseDir + username + "_public.pem";
}

// ✅ Fixed & Simplified signMessage()
std::string signMessage(const std::string& message, const std::string& privateKeyPath, bool isFilePath) {
    std::cout << "[DEBUG] Signing message: " << message << " using key: " << privateKeyPath << std::endl;
    std::string privateKeyContent;

    if (isFilePath) {
        if (!fs::exists(privateKeyPath)) {
            std::cerr << "❌ [ERROR] Private key file not found: " << privateKeyPath << std::endl;
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

    BIO* bio = BIO_new_mem_buf(privateKeyContent.data(), privateKeyContent.size());
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!pkey) {
        std::cerr << "❌ [ERROR] Failed to parse private key.\n";
        return "";
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
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
bool verifyMessage(const std::string& publicKeyPath, const std::string& signature, const std::string& message) {
    if (!fs::exists(publicKeyPath)) {
        std::cerr << "❌ [ERROR] Public key file not found: " << publicKeyPath << std::endl;
        return false;
    }

    std::ifstream pubFile(publicKeyPath);
    std::stringstream buffer;
    buffer << pubFile.rdbuf();
    std::string publicKey = buffer.str();
    pubFile.close();

    if (publicKey.empty()) {
        std::cerr << "❌ [ERROR] Public key is empty: " << publicKeyPath << std::endl;
        return false;
    }

    std::string decodedSignature = base64Decode(signature);
    if (decodedSignature.empty()) {
        std::cerr << "❌ [ERROR] Signature decoding failed!" << std::endl;
        return false;
    }

    BIO* bio = BIO_new_mem_buf(publicKey.data(), publicKey.size());
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!pkey) {
        std::cerr << "❌ [ERROR] Failed to parse public key." << std::endl;
        return false;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pkey);
    EVP_DigestVerifyUpdate(ctx, message.c_str(), message.size());

    bool result = EVP_DigestVerifyFinal(ctx, (unsigned char*)decodedSignature.data(), decodedSignature.size()) == 1;

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return result;
}

} // namespace Crypto
