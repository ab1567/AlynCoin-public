#include "wallet.h"
#include "blockchain.h"
#include "crypto_utils.h"
#include "proof_generator.h"
#include <filesystem>
#include <fstream>
#include <iostream>

namespace fs = std::filesystem;

// Default wallet constructor
Wallet::Wallet() : Wallet("defaultWallet", KEY_DIR, "") {}

// Main constructor: create or load keys for an address
Wallet::Wallet(const std::string& address, const std::string& keyDirectoryPath, const std::string& passphrase)
    : keyDirectory(keyDirectoryPath), walletName(address), address(address) {
    Crypto::ensureKeysDirectory();

    std::string privPath = keyDirectory + address + "_private.pem";
    std::string pubPath  = keyDirectory + address + "_public.pem";

    // Generate keys if missing
    if (!fs::exists(privPath) || !fs::exists(pubPath)) {
        std::cout << "🔐 Generating RSA key pair for address: " << address << std::endl;
        if (!passphrase.empty())
            Crypto::generateKeysForUser(address, passphrase);
        else
            Crypto::generateKeysForUser(address);
    }

    if (!passphrase.empty())
        privateKey = Crypto::loadPrivateKeyDecrypted(privPath, passphrase);
    else
        privateKey = loadKeyFile(privPath);
    publicKey  = loadKeyFile(pubPath);

    // --- Dilithium ---
    dilithiumKeys = Crypto::loadDilithiumKeys(address);
    if (dilithiumKeys.privateKey.empty() || dilithiumKeys.publicKey.empty()) {
        std::cout << "⚠️ Missing Dilithium keys. Generating...\n";
        Crypto::generateDilithiumKeys(address);
        dilithiumKeys = Crypto::loadDilithiumKeys(address);
    }

    // --- Falcon ---
    falconKeys = Crypto::loadFalconKeys(address);
    if (falconKeys.privateKey.empty() || falconKeys.publicKey.empty()) {
        std::cout << "⚠️ Missing Falcon keys. Generating...\n";
        Crypto::generateFalconKeys(address);
        falconKeys = Crypto::loadFalconKeys(address);
    }

    std::cout << "✅ Wallet created successfully!\nAddress: " << address << std::endl;
}

// Alternate constructor: load wallet from explicit private key path
Wallet::Wallet(const std::string& privateKeyPath, const std::string& keyDirectoryPath, const std::string& walletName, const std::string& passphrase)
    : keyDirectory(keyDirectoryPath), walletName(walletName), address(walletName) {
    // Load RSA private key
    if (!fs::exists(privateKeyPath)) {
        throw std::runtime_error("❌ Private key file not found: " + privateKeyPath);
    }
    if (!passphrase.empty())
        privateKey = Crypto::loadPrivateKeyDecrypted(privateKeyPath, passphrase);
    else
        privateKey = loadKeyFile(privateKeyPath);

    // Load RSA public key
    std::string publicKeyPath = privateKeyPath;
    size_t pos = publicKeyPath.find("_private.pem");
    if (pos != std::string::npos)
        publicKeyPath.replace(pos, 12, "_public.pem");

    if (!fs::exists(publicKeyPath)) {
        throw std::runtime_error("❌ Public key file not found: " + publicKeyPath);
    }
    publicKey = loadKeyFile(publicKeyPath);

    // --- Dilithium ---
    dilithiumKeys = Crypto::loadDilithiumKeys(walletName);
    if (dilithiumKeys.privateKey.empty() || dilithiumKeys.publicKey.empty()) {
        throw std::runtime_error("❌ Dilithium keys missing for wallet: " + walletName);
    }

    // --- Falcon ---
    falconKeys = Crypto::loadFalconKeys(walletName);
    if (falconKeys.privateKey.empty() || falconKeys.publicKey.empty()) {
        throw std::runtime_error("❌ Falcon keys missing for wallet: " + walletName);
    }

    // Optional: verify address matches public key
    std::string derived = Crypto::generateAddress(publicKey);
    if (derived != address) {
        std::cerr << "⚠️ Warning: Loaded public key doesn't match provided address.\n";
    }

    std::cout << "✅ Wallet loaded successfully!\nAddress: " << address << std::endl;
}

// Key loader
std::string Wallet::loadKeyFile(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open())
        throw std::runtime_error("❌ Failed to open key file: " + path);
    return std::string((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

bool Wallet::privateKeyExists() const {
    return fs::exists(getPrivateKeyPath());
}

std::string Wallet::getPrivateKeyPath() const {
    return keyDirectory + walletName + "_private.pem";
}

std::string Wallet::getAddress() const { return address; }
std::string Wallet::getPublicKey() const { return publicKey; }
void Wallet::generateDilithiumKeyPair() {
    dilithiumKeys = Crypto::generateDilithiumKeys(walletName);
}
void Wallet::generateFalconKeyPair() {
    falconKeys = Crypto::generateFalconKeys(walletName);
}
std::string Wallet::getDilithiumPublicKey() const {
    if (!dilithiumKeys.publicKeyHex.empty())
        return dilithiumKeys.publicKeyHex;
    return Crypto::toHex(dilithiumKeys.publicKey);
}
std::string Wallet::getFalconPublicKey() const {
    if (!falconKeys.publicKeyHex.empty())
        return falconKeys.publicKeyHex;
    return Crypto::toHex(falconKeys.publicKey);
}
std::string Wallet::getPrivateKey() const { return privateKey; }

double Wallet::getBalance() const {
    return Blockchain::getInstance().getBalance(address);
}

// Transaction creation
Transaction Wallet::createTransaction(const std::string& recipient, double amount) {
    if (amount <= 0)
        throw std::runtime_error("❌ Amount must be greater than zero.");

   int txCount = Blockchain::getInstance().getRecentTransactionCount();
    double burnRate = Transaction::calculateBurnRate(txCount);
    double burnAmount = amount * burnRate;
    amount -= burnAmount;

    std::cout << "🔥 Burned: " << burnAmount << " AlynCoin (" << (burnRate * 100) << "%)\n";

    Transaction tx(address, recipient, amount,
                   "",
                   "",
                   std::time(nullptr));

    tx.signTransaction(dilithiumKeys.privateKey, falconKeys.privateKey);

    return tx;
}

// Sign arbitrary message with this wallet's private key
std::string Wallet::signWithPrivateKey(const std::string& message) {
    if (privateKey.empty()) {
        std::cerr << "❌ RSA private key missing.\n";
        return "";
    }
    return Crypto::signMessage(message, privateKey, false);
}

// Address generator
std::string Wallet::generateAddress(const std::string& publicKey) {
    return Crypto::keccak256(publicKey).substr(0, 40);
}

bool Wallet::saveKeys(const std::string& privKey, const std::string& pubKey) {
    std::ofstream privFile(getPrivateKeyPath());
    std::ofstream pubFile(getPublicKeyPath(walletName, keyDirectory));
    if (!privFile || !pubFile) {
        std::cerr << "❌ Error: Failed to save wallet keys!\n";
        return false;
    }
    privFile << privKey;
    pubFile << pubKey;
    return true;
}

void Wallet::saveToFile(const std::string& filename) const {
    std::ofstream file(filename);
    if (file) {
        file << privateKey << "\n" << publicKey << "\n";
        file << Crypto::toHex(dilithiumKeys.privateKey) << "\n"
             << Crypto::toHex(dilithiumKeys.publicKey) << "\n";
        file << Crypto::toHex(falconKeys.privateKey) << "\n"
             << Crypto::toHex(falconKeys.publicKey) << "\n";
    }
}

Wallet Wallet::loadFromFile(const std::string& filename) {
    std::ifstream file(filename);
    if (!file)
        throw std::runtime_error("❌ Wallet file not found!");

    std::string privKey, pubKey, dilPrivHex, dilPubHex, falcPrivHex, falcPubHex;
    std::getline(file, privKey);
    std::getline(file, pubKey);
    std::getline(file, dilPrivHex);
    std::getline(file, dilPubHex);
    std::getline(file, falcPrivHex);
    std::getline(file, falcPubHex);

    Wallet wallet;
    wallet.privateKey = privKey;
    wallet.publicKey = pubKey;
    wallet.dilithiumKeys.privateKey = Crypto::fromHex(dilPrivHex);
    wallet.dilithiumKeys.publicKey = Crypto::fromHex(dilPubHex);
    wallet.falconKeys.privateKey = Crypto::fromHex(falcPrivHex);
    wallet.falconKeys.publicKey = Crypto::fromHex(falcPubHex);
    wallet.address = Crypto::generateAddress(pubKey);
    return wallet;
}
