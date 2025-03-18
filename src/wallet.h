#ifndef WALLET_H
#define WALLET_H

#include <string>
#include "transaction.h"
#include "crypto_utils.h" // ✅ Ensure CryptoUtils is included

const std::string KEY_DIR = std::string(getenv("HOME") ? getenv("HOME") : "/root") + "/.alyncoin/keys/";
class Wallet {
private:
    std::string privateKey;
    std::string publicKey;
    std::string address;
    std::string keyDirectory; // ✅ New

public:
    Wallet(const std::string& keyPath = "/root/.alyncoin/keys/"); // ✅ Accept key path
    Wallet(const std::string& privateKeyPath, const std::string& keyPath);

    void generateKeyPair();
    std::string getAddress() const;
    std::string getPublicKey() const;
    std::string getPrivateKey() const;
    std::string getPrivateKeyPath() const;
    bool privateKeyExists() const;
    std::string signWithPrivateKey(const std::string& message);
    std::string loadPrivateKey(const std::string& keyPath);
    static std::string generateAddress(const std::string& publicKey);
    double getBalance() const;
    Transaction createTransaction(const std::string& recipient, double amount);
    bool saveKeys(const std::string& privKey, const std::string& pubKey);
    void saveToFile(const std::string& filename) const;
    static Wallet loadFromFile(const std::string& filename);
};

#endif // WALLET_H
