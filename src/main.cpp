#include "blockchain.h"
#include "crypto_utils.h"
#include "miner.h"
#include "network.h"
#include "network/peer_blacklist.h"
#include "wallet.h"
#include <chrono>
#include <iostream>
#include <limits>
#include <thread>
#include "db/db_paths.h"

void clearInputBuffer() {
  std::cin.clear();
  std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
}

int main(int argc, char *argv[]) {
  unsigned short port = 8333;
  std::string dbPath = DBPaths::getBlockchainDB();
  std::string connectIP = "";
  std::string keyDir = "/root/.alyncoin/keys/";
  std::string blacklistPath = "/root/.alyncoin/blacklist";

  // Argument parsing
  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--port" && i + 1 < argc) {
      port = static_cast<unsigned short>(std::stoi(argv[++i]));
      std::cout << "🌐 Using custom port: " << port << std::endl;
    } else if (arg == "--dbpath" && i + 1 < argc) {
      dbPath = argv[++i];
      std::cout << "📁 Using custom DB path: " << dbPath << std::endl;
    } else if (arg == "--connect" && i + 1 < argc) {
      connectIP = argv[++i];
      std::cout << "🔗 Will connect to peer: " << connectIP << std::endl;
    } else if (arg == "--keypath" && i + 1 < argc) {
      keyDir = argv[++i];
      if (keyDir.back() != '/')
        keyDir += '/';
      std::cout << "🔑 Using custom key directory: " << keyDir << std::endl;
    } else {
      std::cerr << "⚠️ Unknown argument ignored: " << arg << std::endl;
    }
  }

  Blockchain &blockchain = Blockchain::getInstance(port, dbPath);
  PeerBlacklist blacklist(blacklistPath, 3); // strike threshold
  Network &network = Network::getInstance(port, &blockchain, &blacklist);

  if (!blockchain.loadFromDB()) {
    std::cerr << "⚠️ Blockchain DB empty! Creating Genesis Block...\n";
    Block genesis = blockchain.createGenesisBlock();
    blockchain.addBlock(genesis);
    blockchain.saveToDB();
  } else {
    std::cout << "✅ Blockchain loaded successfully!\n";
  }

  if (!connectIP.empty()) {
    network.connectToPeer(connectIP, port);
  }

  network.syncWithPeers();
  std::this_thread::sleep_for(std::chrono::seconds(2));

  std::string minerAddress;
  bool running = true;

  while (running) {
    std::cout << "\n=== AlynCoin Node CLI ===\n";
    std::cout << "1. Add Transaction\n";
    std::cout << "2. Mine Block\n";
    std::cout << "3. Print Blockchain\n";
    std::cout << "4. Start Mining Loop\n";
    std::cout << "5. Sync Blockchain\n";
    std::cout << "6. View Dev Fund Info\n";
    std::cout << "7. Exit\n";
    std::cout << "Choose an option: ";

    int choice;
    std::cin >> choice;
    if (std::cin.fail()) {
      clearInputBuffer();
      std::cout << "Invalid input!\n";
      continue;
    }

    switch (choice) {
    case 1: {
      std::string sender, recipient;
      double amount;
      std::cout << "Enter sender: ";
      std::cin >> sender;
      if (sender == "DevFundWallet") {
        std::cout << "Transactions from DevFundWallet are restricted.\n";
        break;
      }
      std::cout << "Enter recipient: ";
      std::cin >> recipient;
      std::cout << "Enter amount: ";
      std::cin >> amount;

      if (amount <= 0) {
        std::cout << "Invalid amount!\n";
        break;
      }

      Crypto::ensureUserKeys(sender);

      DilithiumKeyPair dilKeys = Crypto::loadDilithiumKeys(sender);
      FalconKeyPair falKeys = Crypto::loadFalconKeys(sender);

      if (dilKeys.privateKey.empty() || falKeys.privateKey.empty()) {
        std::cerr << "❌ Error: Missing private keys. Cannot sign transaction.\n";
        break;
      }

      Transaction tx(sender, recipient, amount, "", "", time(nullptr));
      tx.signTransaction(dilKeys.privateKey, falKeys.privateKey);

      if (!tx.isValid(Crypto::toHex(dilKeys.publicKey),
                      Crypto::toHex(falKeys.publicKey))) {
        std::cout << "Invalid transaction! Signature check failed.\n";
        break;
      }

      blockchain.addTransaction(tx);
      network.broadcastTransaction(tx);
      std::cout << "Transaction added & broadcasted!\n";
      break;
    }

    case 2: {
      std::cout << "Enter miner address: ";
      std::cin >> minerAddress;
      if (minerAddress.empty()) {
        std::cout << "Invalid miner address!\n";
        break;
      }

      std::cout << "Mining block...\n";

      Block minedBlock = blockchain.mineBlock(minerAddress);
      if (!minedBlock.getHash().empty()) {
        blockchain.saveToDB();
        blockchain.saveTransactionsToDB();
        network.broadcastBlock(minedBlock);
        blockchain.reloadBlockchainState();
        std::cout << "Block mined, saved, synced!\n";
      } else {
        std::cout << "Mining failed!\n";
      }
      break;
    }

    case 3:
      blockchain.printBlockchain();
      break;

    case 4: {
      std::cout << "Enter miner address: ";
      std::cin >> minerAddress;
      if (minerAddress.empty()) {
        std::cout << "Invalid miner address!\n";
        break;
      }
      std::cout << "Manual mining started for: " << minerAddress << "\n";
      Miner::startMiningProcess(minerAddress);
      break;
    }

    case 5:
      std::cout << "Syncing with peers...\n";
      network.syncWithPeers();
      break;

    case 6:
      std::cout << "\n=== Dev Fund Information ===\n";
      std::cout << "Address: DevFundWallet\n";
      std::cout << "Balance: " << blockchain.getBalance("DevFundWallet") << " AlynCoin\n";
      break;

    case 7:
      std::cout << "Exiting AlynCoin Node... Goodbye!\n";
      running = false;
      break;

    default:
      std::cout << "Invalid choice! Try again.\n";
    }
  }

  return 0;
}
