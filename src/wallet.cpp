#include "wallet.h"
#include "blockchain.h"
#include <fstream>
#include <thread>
#include <iostream>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include "crypto_utils.h"
#include <filesystem>
namespace fs = std::filesystem;


#define PRIVATE_KEY_FILE(wallet_address) (KEY_DIR + wallet_address + "_private.pem")
#define PUBLIC_KEY_FILE(wallet_address) (KEY_DIR + wallet_address + "_public.pem")

// Constructor: Loads keys or generates new ones if missing
Wallet::Wallet(const std::string& keyDirectoryPath) : keyDirectory(keyDirectoryPath) {
    if (!privateKeyExists()) {
        generateKeyPair();
    } else {
        std::ifstream pubFile(getPublicKeyPath());
        if (pubFile) {
            publicKey.assign((std::istreambuf_iterator<char>(pubFile)), std::istreambuf_iterator<char>());
            address = generateAddress(publicKey);
        } else {
            std::cerr << "❌ Error: Could not load public key. Regenerating new key pair...\n";
            generateKeyPair();
            return;
        }

        std::ifstream privFile(getPrivateKeyPath());
        if (privFile) {
            privateKey.assign((std::istreambuf_iterator<char>(privFile)), std::istreambuf_iterator<char>());
        } else {
            std::cerr << "❌ Error: Could not load private key. Regenerating new key pair...\n";
            generateKeyPair();
        }
    }
}

// Constructor to Load Wallet from Private Key File
Wallet::Wallet(const std::string& privateKeyPath, const std::string& keyDirectoryPath) : keyDirectory(keyDirectoryPath) {
    std::ifstream privFile(privateKeyPath);
    if (!privFile) {
        throw std::runtime_error("❌ Error: Could not open private key file: " + privateKeyPath);
    }

    privateKey.assign((std::istreambuf_iterator<char>(privFile)), std::istreambuf_iterator<char>());

    std::string publicKeyPath = privateKeyPath;
    size_t pos = publicKeyPath.find("_private.pem");
    if (pos != std::string::npos) {
        publicKeyPath.replace(pos, 12, "_public.pem");
    }

    if (!fs::exists(publicKeyPath)) {
        std::cerr << "⚠️ Public key missing! Regenerating...\n";
        std::string username = fs::path(privateKeyPath).stem().string();
        Crypto::generateKeysForUser(username);
    }

    std::ifstream pubFile(publicKeyPath);
    if (pubFile) {
        publicKey.assign((std::istreambuf_iterator<char>(pubFile)), std::istreambuf_iterator<char>());
        address = generateAddress(publicKey);
    } else {
        throw std::runtime_error("❌ Error: Public key file still missing after regeneration attempt!");
    }
}

// ✅ Load Private Key with Verification Before Signing
std::string Wallet::loadPrivateKey(const std::string& keyPath) {
    if (!fs::exists(keyPath)) {
        std::cerr << "❌ [ERROR] Private key file not found: " << keyPath << std::endl;
        return "";
    }

    std::ifstream keyFile(keyPath);
    if (!keyFile.is_open()) {
        std::cerr << "❌ [ERROR] Cannot open private key file: " << keyPath << std::endl;
        return "";
    }

    std::string privateKey((std::istreambuf_iterator<char>(keyFile)), std::istreambuf_iterator<char>());
    keyFile.close();

    if (privateKey.empty() || privateKey.size() < 64) {
        std::cerr << "❌ [ERROR] Invalid private key! Aborting signing process.\n";
        return "";
    }

    return privateKey;
}

// ✅ Generate RSA Key Pair (Updated for OpenSSL 3.0+)
void Wallet::generateKeyPair() {
    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);

    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 ||
        EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        std::cerr << "❌ Error generating RSA key pair!" << std::endl;
        if (ctx) EVP_PKEY_CTX_free(ctx);
        if (pkey) EVP_PKEY_free(pkey);
        return;
    }

    BIO* pri = BIO_new(BIO_s_mem());
    BIO* pub = BIO_new(BIO_s_mem());

    if (!PEM_write_bio_PrivateKey(pri, pkey, nullptr, nullptr, 0, nullptr, nullptr) ||
        !PEM_write_bio_PUBKEY(pub, pkey)) {
        std::cerr << "❌ Error writing key pair to memory!" << std::endl;
        BIO_free(pri);
        BIO_free(pub);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return;
    }

    BUF_MEM* priPtr;
    BUF_MEM* pubPtr;
    BIO_get_mem_ptr(pri, &priPtr);
    BIO_get_mem_ptr(pub, &pubPtr);

    if (!priPtr || !pubPtr || priPtr->length == 0 || pubPtr->length == 0) {
        std::cerr << "❌ Error: Generated keys are empty!" << std::endl;
        BIO_free(pri);
        BIO_free(pub);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return;
    }

    privateKey.assign(priPtr->data, priPtr->length);
    publicKey.assign(pubPtr->data, pubPtr->length);

    // ✅ Free memory to prevent leaks
    BIO_free(pri);
    BIO_free(pub);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
}

// ✅ Check if Private Key Exists
bool Wallet::privateKeyExists() const {
    return fs::exists(getPrivateKeyPath());
}
// ✅ Sign Message with Private Key (Fix CryptoUtils Reference)
std::string Wallet::signWithPrivateKey(const std::string& message) {
    std::string privateKeyPath = getPrivateKeyPath();  // ✅ Get correct private key path

    if (!fs::exists(privateKeyPath)) {
        std::cerr << "❌ [ERROR] Private key file not found: " << privateKeyPath << std::endl;
        return "";
    }

    // ✅ Read private key from file
    std::ifstream keyFile(privateKeyPath);
    if (!keyFile.is_open()) {
        std::cerr << "❌ [ERROR] Failed to open private key file: " << privateKeyPath << std::endl;
        return "";
    }

    std::stringstream buffer;
    buffer << keyFile.rdbuf();
    keyFile.close();
    std::string privateKeyContent = buffer.str();  // ✅ Now we have the actual key content

    // ✅ Correct function call
    std::string signature = Crypto::signMessage(message, privateKeyContent, false);  

    if (signature.empty()) {
        std::cerr << "❌ [ERROR] Signing failed for message: " << message << std::endl;
        return "";
    }

    return signature;
}

// ✅ Generate Address from Public Key (Keccak-256 Hash) - Fix CryptoUtils Reference
std::string Wallet::generateAddress(const std::string& publicKey) {
    return Crypto::keccak256(publicKey).substr(0, 40);
}

// ✅ When saving keys, use keyDirectory:
bool Wallet::saveKeys(const std::string& privKey, const std::string& pubKey) {
    std::string privPath = getPrivateKeyPath();
    std::string pubPath = getPublicKeyPath();

    std::ofstream privFile(privPath);
    std::ofstream pubFile(pubPath);

    if (!privFile || !pubFile) {
        std::cerr << "❌ Error: Failed to save wallet keys!\n";
        return false;
    }

    privFile << privKey;
    pubFile << pubKey;

    privFile.close();
    pubFile.close();
    return true;
}

//
std::string Wallet::getPrivateKeyPath() const {
    return "/root/.alyncoin/keys/" + address + "_private.pem";
}
// ✅ Getters
std::string Wallet::getAddress() const { return address; }
std::string Wallet::getPublicKey() const { return publicKey; }
std::string Wallet::getPrivateKey() const { return privateKey; }

// ✅ **Create Transaction with Smart Burn and Protobuf**
Transaction Wallet::createTransaction(const std::string& recipient, double amount) {
    if (amount <= 0) {
        std::cerr << "❌ [ERROR] Invalid transaction amount!\n";
        throw std::runtime_error("Transaction amount must be greater than zero.");
    }

    int recentTxCount = Blockchain::getInstance().getRecentTransactionCount();
    double burnRate = Transaction::calculateBurnRate(recentTxCount);  // ✅ Use static call
    double burnAmount = amount * burnRate;
    amount -= burnAmount;
    
    std::cout << "🔥 Burned " << burnAmount << " AlynCoin (" << (burnRate * 100) << "%)" << std::endl;

    std::string message = address + recipient + std::to_string(amount);
    std::string signature = signWithPrivateKey(message);

    return Transaction(address, recipient, amount, signature);
}

// ✅ Save Wallet to File
void Wallet::saveToFile(const std::string& filename) const {
    std::ofstream file(filename);
    file << privateKey << std::endl << publicKey << std::endl;
}

// ✅ Load Wallet from File
Wallet Wallet::loadFromFile(const std::string& filename) {
    std::ifstream file(filename);
    if (!file) throw std::runtime_error("Could not open wallet file!");

    std::string privKey, pubKey;
    std::getline(file, privKey);
    std::getline(file, pubKey);

    Wallet wallet;
    wallet.privateKey = privKey;
    wallet.publicKey = pubKey;
    wallet.address = generateAddress(pubKey);
    return wallet;
}
