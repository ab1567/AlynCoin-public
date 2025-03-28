#include "blockchain.h"
#include "cli/peer_blacklist_cli.h"
#include "crypto_utils.h"
#include "network.h"
#include "network/peer_blacklist.h"
#include "wallet.h"
#include <fstream>
#include <iostream>
#include <json/json.h>
#include <limits>
#include <string>
#include <filesystem>

void printMenu() {
  std::cout << "\n=== AlynCoin Wallet CLI ===\n";
  std::cout << "1. Generate new wallet\n";
  std::cout << "2. Load existing wallet\n";
  std::cout << "3. Check balance\n";
  std::cout << "4. Send transaction\n";
  std::cout << "5. Mine block\n";
  std::cout << "6. Print blockchain\n";
  std::cout << "7. View Dev Fund Info\n";
  std::cout << "8. Manage Peer Blacklist\n";
  std::cout << "9. Exit\n";
  std::cout << "Choose an option: ";
}

void printBlacklistMenu() {
  std::cout << "\n=== Peer Blacklist Menu ===\n";
  std::cout << "1. View Blacklist\n";
  std::cout << "2. Add Peer\n";
  std::cout << "3. Remove Peer\n";
  std::cout << "4. Clear Blacklist\n";
  std::cout << "5. Back to Main Menu\n";
  std::cout << "Choose an option: ";
}

int cliMain(int argc, char *argv[]) {
  unsigned short port = 8333;
  std::string dbPath = "";
  std::string connectPeer = "";
  std::string keyDir = "/root/.alyncoin/keys/";
  std::string blacklistPath = "/root/.alyncoin/blacklist";

  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--dbpath" && i + 1 < argc) {
      dbPath = argv[++i];
    } else if (arg == "--connect" && i + 1 < argc) {
      connectPeer = argv[++i];
    } else if (arg == "--keypath" && i + 1 < argc) {
      keyDir = argv[++i];
      if (keyDir.back() != '/') keyDir += '/';
      std::cout << "Using custom key directory: " << keyDir << std::endl;
    } else {
      try {
        port = std::stoi(arg);
        std::cout << "Using custom port: " << port << std::endl;
      } catch (...) {
        std::cerr << "Unknown argument ignored: " << arg << "\n";
      }
    }
  }

  Wallet *wallet = nullptr;
  Blockchain &blockchain = Blockchain::getInstance(port, dbPath);
  PeerBlacklist peerBlacklist(blacklistPath, 3);
  Network &network = Network::getInstance(port, &blockchain, &peerBlacklist);

  if (!connectPeer.empty()) {
    size_t colonPos = connectPeer.find(':');
    if (colonPos != std::string::npos) {
      std::string ip = connectPeer.substr(0, colonPos);
      int peerPort = std::stoi(connectPeer.substr(colonPos + 1));
      if (!network.connectToNode(ip, peerPort)) {
        std::cerr << "Failed to connect to AlynCoin node at " << connectPeer << "\n";
      } else {
        std::cout << "Connected to AlynCoin Node at " << connectPeer << "\n";
      }
    }
  }

  bool running = true;
  while (running) {
    printMenu();
    int choice;
    std::cin >> choice;

    if (std::cin.fail()) {
      std::cin.clear();
      std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
      std::cout << "Invalid input. Please enter a valid option.\n";
      continue;
    }

    switch (choice) {
    case 1: {
      std::string newAddress;
      std::cout << "Enter a new wallet address (leave blank for auto-generated): ";
      std::cin.ignore();
      std::getline(std::cin, newAddress);

      if (!newAddress.empty()) {
        if (newAddress.length() > 40 || !std::all_of(newAddress.begin(), newAddress.end(), ::isalnum)) {
          std::cout << "❌ Invalid address. Must be alphanumeric and <= 40 characters.\n";
          break;
        }
        std::string privPath = keyDir + newAddress + "_private.pem";
        if (std::filesystem::exists(privPath)) {
          std::cout << "⚠️ Wallet already exists. Use option 2 to load.\n";
          break;
        }

        if (wallet) delete wallet;
        try {
          wallet = new Wallet(newAddress, keyDir);
          std::cout << "✅ New wallet created!\nAddress: " << wallet->getAddress() << std::endl;
        } catch (const std::exception &e) {
          std::cerr << "❌ Wallet creation failed: " << e.what() << std::endl;
          wallet = nullptr;
        }

      } else {
        std::string tempID = Crypto::generateRandomHex(12);
        std::string privPem = Crypto::generatePrivateKey(tempID, "unused");
        std::string pubPem = Crypto::getPublicKey(tempID);
        std::string derivedAddress = Crypto::generateAddress(pubPem);

        std::ofstream(keyDir + derivedAddress + "_private.pem") << privPem;
        std::ofstream(keyDir + derivedAddress + "_public.pem") << pubPem;

        if (wallet) delete wallet;
        try {
          wallet = new Wallet(derivedAddress, keyDir);
          std::cout << "✅ New wallet created!\nAddress: " << wallet->getAddress() << std::endl;
        } catch (const std::exception &e) {
          std::cerr << "❌ Wallet creation failed: " << e.what() << std::endl;
          wallet = nullptr;
        }
      }
      break;
    }

    case 2: {
      std::string walletAddress;
      std::cout << "Enter wallet address to load: ";
      std::cin >> walletAddress;

      std::string privPath = keyDir + walletAddress + "_private.pem";
      std::string dilPath = keyDir + walletAddress + "_dilithium.key";
      std::string falPath = keyDir + walletAddress + "_falcon.key";

      if (!std::filesystem::exists(privPath) || !std::filesystem::exists(dilPath) || !std::filesystem::exists(falPath)) {
        std::cerr << "❌ Missing required key files for wallet: " << walletAddress << "\n";
        break;
      }

      if (wallet) delete wallet;
      try {
        wallet = new Wallet(privPath, keyDir, walletAddress);
        std::cout << "✅ Wallet loaded successfully!\nAddress: " << wallet->getAddress() << std::endl;
      } catch (const std::exception &e) {
        std::cerr << "❌ Wallet loading failed: " << e.what() << std::endl;
        wallet = nullptr;
      }
      break;
    }

    case 3: {
      if (!wallet) {
        std::cout << "Load or create a wallet first!\n";
        break;
      }
      std::cout << "Checking balance for: " << wallet->getAddress() << "\n";
      std::cout << "Balance: " << blockchain.getBalance(wallet->getAddress()) << " AlynCoin\n";
      break;
    }

    case 4: {
      if (!wallet) {
        std::cout << "Load or create a wallet first!\n";
        break;
      }
      std::string recipient;
      double amount;
      std::cout << "Enter recipient address: ";
      std::cin >> recipient;
      std::cout << "Enter amount: ";
      std::cin >> amount;
      if (amount <= 0) {
        std::cout << "Invalid amount!\n";
        break;
      }

      std::string sender = wallet->getAddress();
      auto dilPriv = Crypto::loadDilithiumKeys(sender);
      auto falPriv = Crypto::loadFalconKeys(sender);

      Transaction tx(sender, recipient, amount, "", "", time(nullptr));
      tx.signTransaction(dilPriv.privateKey, falPriv.privateKey);

      if (!tx.getSignatureDilithium().empty() && !tx.getSignatureFalcon().empty()) {
        blockchain.addTransaction(tx);
        network.broadcastTransaction(tx);
        std::cout << "Transaction created and broadcasted!\n";
      } else {
        std::cerr << "Invalid transaction! Signature check failed.\n";
      }
      break;
    }

    case 5: {
      if (!wallet) {
        std::cout << "Load or create a wallet first!\n";
        break;
      }

      std::string addr = wallet->getAddress();
      auto dilPriv = Crypto::loadDilithiumKeys(addr);
      auto falPriv = Crypto::loadFalconKeys(addr);

      std::cout << "Starting mining with address: " << addr << std::endl;
      Block mined = blockchain.minePendingTransactions(addr, dilPriv.privateKey, falPriv.privateKey);

      if (mined.getHash().empty()) {
        std::cout << "❌ Mining failed or returned empty block.\n";
      } else {
        blockchain.saveToDB();
        std::cout << "✅ Block mined! Hash: " << mined.getHash() << std::endl;
      }
      break;
    }

    case 6:
      std::cout << "=== AlynCoin Blockchain ===\n";
      std::cout << Json::writeString(Json::StreamWriterBuilder(), blockchain.toJSON()) << std::endl;
      break;

    case 7:
      std::cout << "\n=== Dev Fund Information ===\n";
      std::cout << "Address: DevFundWallet\n";
      std::cout << "Balance: " << blockchain.getBalance("DevFundWallet") << " AlynCoin\n";
      break;

    case 8: {
      bool blacklistRunning = true;
      while (blacklistRunning) {
        printBlacklistMenu();
        int blChoice;
        std::cin >> blChoice;
        if (std::cin.fail()) {
          std::cin.clear();
          std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
          std::cout << "Invalid input!\n";
          continue;
        }
        switch (blChoice) {
          case 1: showBlacklist(&peerBlacklist); break;
          case 2: {
            std::string peerID, reason;
            std::cout << "Enter peer ID: ";
            std::cin >> peerID;
            std::cout << "Enter reason: ";
            std::cin.ignore();
            std::getline(std::cin, reason);
            addPeer(&peerBlacklist, peerID, reason);
            break;
          }
          case 3: {
            std::string peerID;
            std::cout << "Enter peer ID: ";
            std::cin >> peerID;
            removePeer(&peerBlacklist, peerID);
            break;
          }
          case 4: clearBlacklist(&peerBlacklist); break;
          case 5: blacklistRunning = false; break;
          default: std::cout << "Invalid choice!\n";
        }
      }
      break;
    }

    case 9: running = false; break;
    default: std::cout << "Invalid choice! Please select a valid option.\n";
    }
  }

  if (wallet) delete wallet;
  return 0;
}

int main(int argc, char **argv) {
  return cliMain(argc, argv);
}
