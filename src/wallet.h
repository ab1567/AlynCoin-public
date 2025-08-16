#ifndef WALLET_H
#define WALLET_H

#include "crypto_utils.h"
#include "transaction.h"
#include <string>
#include <vector>
#include "db/db_paths.h"

const std::string WALLET_KEY_DIR =
    DBPaths::getKeyDir();

class Wallet {
private:
  std::string privateKey;
  std::string publicKey;
  std::string address;
  std::string keyDirectory;
  std::string walletName;

  DilithiumKeyPair dilithiumKeys;
  FalconKeyPair falconKeys;

  std::string loadKeyFile(const std::string &keyPath);

public:
  // Constructors
  Wallet(); // Default
  Wallet(const std::string &address, const std::string &keyDirectoryPath, const std::string &passphrase = ""); // New or existing wallet
  Wallet(const std::string &privateKeyPath, const std::string &keyDirectoryPath, const std::string &address, const std::string &passphrase = ""); // Load from private key

  // Key management
  void generateKeyPair(); // RSA
  void generateDilithiumKeyPair();
  void generateFalconKeyPair();

  // Info
  std::string getAddress() const;
  std::string getPublicKey() const;
  std::string getDilithiumPublicKey() const;
  std::string getFalconPublicKey() const;
  std::string getPrivateKey() const;
  std::string getPrivateKeyPath() const;
  bool privateKeyExists() const;
  static std::string generateAddress(const std::string &publicKey);

  // Signing
  std::string signWithPrivateKey(const std::string &message);

  // Wallet file storage
  bool saveKeys(const std::string &privKey, const std::string &pubKey);
  void saveToFile(const std::string &filename) const;
  static Wallet loadFromFile(const std::string &filename);

  // Transaction
  double getBalance() const;
  Transaction createTransaction(const std::string &recipient, double amount);
};

#endif // WALLET_H
