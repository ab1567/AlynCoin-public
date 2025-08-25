#include "wallet.h"
#include "blockchain.h"
#include "crypto_utils.h"
#include "proof_generator.h"
#include "wallet_crypto.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>
#include <sodium.h>

namespace fs = std::filesystem;

// Default wallet constructor
// Use the main constructor with default passphrase to avoid ambiguity with the
// overload that accepts a private key path.
Wallet::Wallet() : Wallet("defaultWallet", KEY_DIR) {}

// Main constructor: create or load keys for an address
Wallet::Wallet(const std::string& address, const std::string& keyDirectoryPath, const std::string& passphrase)
    : keyDirectory(keyDirectoryPath), walletName(address), address(address) {
    Crypto::ensureKeysDirectory();

    std::string privPath = keyDirectory + address + "_private.pem";
    std::string pubPath  = keyDirectory + address + "_public.pem";

    // Generate keys if missing
    if (!fs::exists(privPath) || !fs::exists(pubPath)) {
        std::cout << "🔐 Generating RSA key pair for address: " << address << std::endl;
        Crypto::generateKeysForUser(address); // generate without encryption
        if (!passphrase.empty()) {
            std::string plain = loadKeyFile(privPath);
            std::vector<unsigned char> buf(plain.begin(), plain.end());
            WalletCrypto::encryptToFile(privPath, buf, passphrase, "interactive", 1);
            sodium_memzero(buf.data(), buf.size());
        }
    }

    // Load RSA private key (with migration)
    if (!passphrase.empty()) {
        bool legacy = true;
        {
            std::ifstream in(privPath, std::ios::binary);
            WalletCrypto::FileHeader hdr;
            if (in.read(reinterpret_cast<char*>(&hdr), sizeof(hdr)))
                legacy = std::memcmp(hdr.magic, "ACWK", 4) != 0;
        }
        if (legacy) {
            fs::copy_file(privPath, privPath + ".bak", fs::copy_options::overwrite_existing);
            std::string plain = loadKeyFile(privPath);
            std::vector<unsigned char> buf(plain.begin(), plain.end());
            WalletCrypto::encryptToFile(privPath, buf, passphrase, "interactive", 1);
            sodium_memzero(buf.data(), buf.size());
            privateKey = plain;
        } else {
            std::vector<unsigned char> dec;
            if (!WalletCrypto::decryptFromFile(privPath, dec, passphrase))
                throw std::runtime_error("❌ Failed to decrypt private key");
            privateKey.assign(dec.begin(), dec.end());
            sodium_memzero(dec.data(), dec.size());
        }
    } else {
        privateKey = loadKeyFile(privPath);
    }
    publicKey  = loadKeyFile(pubPath);

    // --- Dilithium ---
    std::string dilPriv = keyDirectory + address + "_dilithium.key";
    std::string dilPub  = keyDirectory + address + "_dilithium.pub";
    if (!fs::exists(dilPriv) || !fs::exists(dilPub)) {
        std::cout << "⚠️ Missing Dilithium keys. Generating...\n";
        Crypto::generateDilithiumKeys(address);
    }
    if (!passphrase.empty()) {
        bool legacy = true;
        {
            std::ifstream in(dilPriv, std::ios::binary);
            WalletCrypto::FileHeader hdr;
            if (in.read(reinterpret_cast<char*>(&hdr), sizeof(hdr)))
                legacy = std::memcmp(hdr.magic, "ACWK", 4) != 0;
        }
        if (legacy) {
            fs::copy_file(dilPriv, dilPriv + ".bak", fs::copy_options::overwrite_existing);
            std::ifstream raw(dilPriv, std::ios::binary);
            std::vector<unsigned char> plain((std::istreambuf_iterator<char>(raw)), {});
            WalletCrypto::encryptToFile(dilPriv, plain, passphrase, "interactive", 2);
            sodium_memzero(plain.data(), plain.size());
        }
        std::vector<unsigned char> dec;
        if (!WalletCrypto::decryptFromFile(dilPriv, dec, passphrase))
            throw std::runtime_error("❌ Failed to decrypt Dilithium key");
        dilithiumKeys.privateKey = dec;
        dilithiumKeys.privateKeyHex = Crypto::toHex(dec);
        sodium_memzero(dec.data(), dec.size());
        std::ifstream pub(dilPub, std::ios::binary);
        dilithiumKeys.publicKey.assign((std::istreambuf_iterator<char>(pub)), {});
        dilithiumKeys.publicKeyHex = Crypto::toHex(dilithiumKeys.publicKey);
    } else {
        dilithiumKeys = Crypto::loadDilithiumKeys(address);
    }

    // --- Falcon ---
    std::string falPriv = keyDirectory + address + "_falcon.key";
    std::string falPub  = keyDirectory + address + "_falcon.pub";
    if (!fs::exists(falPriv) || !fs::exists(falPub)) {
        std::cout << "⚠️ Missing Falcon keys. Generating...\n";
        Crypto::generateFalconKeys(address);
    }
    if (!passphrase.empty()) {
        bool legacy = true;
        {
            std::ifstream in(falPriv, std::ios::binary);
            WalletCrypto::FileHeader hdr;
            if (in.read(reinterpret_cast<char*>(&hdr), sizeof(hdr)))
                legacy = std::memcmp(hdr.magic, "ACWK", 4) != 0;
        }
        if (legacy) {
            fs::copy_file(falPriv, falPriv + ".bak", fs::copy_options::overwrite_existing);
            std::ifstream raw(falPriv, std::ios::binary);
            std::vector<unsigned char> plain((std::istreambuf_iterator<char>(raw)), {});
            WalletCrypto::encryptToFile(falPriv, plain, passphrase, "interactive", 3);
            sodium_memzero(plain.data(), plain.size());
        }
        std::vector<unsigned char> dec;
        if (!WalletCrypto::decryptFromFile(falPriv, dec, passphrase))
            throw std::runtime_error("❌ Failed to decrypt Falcon key");
        falconKeys.privateKey = dec;
        falconKeys.privateKeyHex = Crypto::toHex(dec);
        sodium_memzero(dec.data(), dec.size());
        std::ifstream pub(falPub, std::ios::binary);
        falconKeys.publicKey.assign((std::istreambuf_iterator<char>(pub)), {});
        falconKeys.publicKeyHex = Crypto::toHex(falconKeys.publicKey);
    } else {
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
    if (!passphrase.empty()) {
        bool legacy = true;
        {
            std::ifstream in(privateKeyPath, std::ios::binary);
            WalletCrypto::FileHeader hdr;
            if (in.read(reinterpret_cast<char*>(&hdr), sizeof(hdr)))
                legacy = std::memcmp(hdr.magic, "ACWK", 4) != 0;
        }
        if (legacy) {
            fs::copy_file(privateKeyPath, privateKeyPath + ".bak", fs::copy_options::overwrite_existing);
            std::string plain = loadKeyFile(privateKeyPath);
            std::vector<unsigned char> buf(plain.begin(), plain.end());
            WalletCrypto::encryptToFile(privateKeyPath, buf, passphrase, "interactive", 1);
            sodium_memzero(buf.data(), buf.size());
            privateKey = plain;
        } else {
            std::vector<unsigned char> dec;
            if (!WalletCrypto::decryptFromFile(privateKeyPath, dec, passphrase))
                throw std::runtime_error("❌ Failed to decrypt private key");
            privateKey.assign(dec.begin(), dec.end());
            sodium_memzero(dec.data(), dec.size());
        }
    } else {
        privateKey = loadKeyFile(privateKeyPath);
    }

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
    std::string dilPriv = keyDirectory + walletName + "_dilithium.key";
    std::string dilPub  = keyDirectory + walletName + "_dilithium.pub";
    if (!fs::exists(dilPriv) || !fs::exists(dilPub))
        throw std::runtime_error("❌ Dilithium keys missing for wallet: " + walletName);
    if (!passphrase.empty()) {
        std::vector<unsigned char> dec;
        if (!WalletCrypto::decryptFromFile(dilPriv, dec, passphrase))
            throw std::runtime_error("❌ Failed to decrypt Dilithium key");
        dilithiumKeys.privateKey = dec;
        dilithiumKeys.privateKeyHex = Crypto::toHex(dec);
        sodium_memzero(dec.data(), dec.size());
        std::ifstream pub(dilPub, std::ios::binary);
        dilithiumKeys.publicKey.assign((std::istreambuf_iterator<char>(pub)), {});
        dilithiumKeys.publicKeyHex = Crypto::toHex(dilithiumKeys.publicKey);
    } else {
        dilithiumKeys = Crypto::loadDilithiumKeys(walletName);
    }

    // --- Falcon ---
    std::string falPriv = keyDirectory + walletName + "_falcon.key";
    std::string falPub  = keyDirectory + walletName + "_falcon.pub";
    if (!fs::exists(falPriv) || !fs::exists(falPub))
        throw std::runtime_error("❌ Falcon keys missing for wallet: " + walletName);
    if (!passphrase.empty()) {
        std::vector<unsigned char> dec;
        if (!WalletCrypto::decryptFromFile(falPriv, dec, passphrase))
            throw std::runtime_error("❌ Failed to decrypt Falcon key");
        falconKeys.privateKey = dec;
        falconKeys.privateKeyHex = Crypto::toHex(dec);
        sodium_memzero(dec.data(), dec.size());
        std::ifstream pub(falPub, std::ios::binary);
        falconKeys.publicKey.assign((std::istreambuf_iterator<char>(pub)), {});
        falconKeys.publicKeyHex = Crypto::toHex(falconKeys.publicKey);
    } else {
        falconKeys = Crypto::loadFalconKeys(walletName);
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
