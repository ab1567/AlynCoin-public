// ───────────────────────────────────────────────────────────────
// 🧱 AlynCoin Full Node - Main Entry Point (main.cpp)
// ───────────────────────────────────────────────────────────────
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

// ───────────────────────────────────────────────────────────────
// 🧹 Helper: Clear std::cin on bad input
// ───────────────────────────────────────────────────────────────
void clearInputBuffer() {
  std::cin.clear();
  std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
}

// ───────────────────────────────────────────────────────────────
// 🏁 Main Function Entry
// ───────────────────────────────────────────────────────────────
int main(int argc, char *argv[]) {
  unsigned short port = 8333;
  std::string dbPath = DBPaths::getBlockchainDB();
  std::string connectIP = "";
  std::string keyDir = "/root/.alyncoin/keys/";
  std::string blacklistPath = "/root/.alyncoin/blacklist";

// ───────────────────────────────────────────────────────────────
// 🧪 Special CLI Mode: Headless Mining (for GUI integration)
// ───────────────────────────────────────────────────────────────
if (argc == 3 && (std::string(argv[1]) == "--mineonce" || std::string(argv[1]) == "--mine-once")) {
  std::string minerAddress = argv[2];
  std::cout << "⛏️ Mining single block for: " << minerAddress << "...\n";

  Blockchain &blockchain = Blockchain::getInstanceNoNetwork(); // ✅ skip peer binding
  if (!blockchain.loadFromDB()) {
    std::cerr << "❌ Blockchain not loaded.\n";
    return 1;
  }

  Block minedBlock = blockchain.mineBlock(minerAddress);
  if (!minedBlock.getHash().empty()) {
    blockchain.saveToDB();
    blockchain.reloadBlockchainState();

    std::cout << "✅ Block mined by: " << minerAddress << "\n";
    std::cout << "🧱 Block Hash: " << minedBlock.getHash() << "\n";
    std::cout << "✅ Block added to chain successfully.\n";
  } else {
    std::cerr << "⚠️ Mining failed. No valid transactions or error occurred.\n";
  }
  return 0;
}
//----------------------------
//----------------------------
if (argc == 3 && (std::string(argv[1]) == "--mineloop" || std::string(argv[1]) == "--mine-loop")) {
  std::string minerAddress = argv[2];
  std::cout << "🔁 Starting mining loop for: " << minerAddress << "\n";

  Blockchain &blockchain = Blockchain::getInstanceNoNetwork();
  if (!blockchain.loadFromDB()) {
    std::cerr << "❌ Blockchain not loaded.\n";
    return 1;
  }

  while (true) {
    Block minedBlock = blockchain.mineBlock(minerAddress);
    if (!minedBlock.getHash().empty()) {
      blockchain.saveToDB();
      blockchain.reloadBlockchainState();
      std::cout << "✅ Block mined by: " << minerAddress << "\n";
      std::cout << "🧱 Block Hash: " << minedBlock.getHash() << "\n";
    } else {
      std::cerr << "⚠️ Mining failed or no valid transactions.\n";
    }
    std::this_thread::sleep_for(std::chrono::seconds(2));
  }

  return 0; // Just in case, though it'll never hit here.
}

// ───────────────────────────────────────────────────────────────
// 🔧 Argument Parsing
// ───────────────────────────────────────────────────────────────
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
      if (keyDir.back() != '/') keyDir += '/';
      std::cout << "🔑 Using custom key directory: " << keyDir << std::endl;
    } else if (arg[0] != '-') {
      try {
        port = static_cast<unsigned short>(std::stoi(arg));
        std::cout << "🌐 Positional port override: " << port << std::endl;
      } catch (...) {
        std::cerr << "⚠️ Invalid positional argument: " << arg << std::endl;
      }
    } else {
      std::cerr << "⚠️ Unknown argument ignored: " << arg << std::endl;
    }
  }

// ───────────────────────────────────────────────────────────────
// 🧠 Init Core Components: Blockchain, Network, Peers
// ───────────────────────────────────────────────────────────────
  Blockchain &blockchain = Blockchain::getInstance(port, dbPath);
  PeerBlacklist blacklist(blacklistPath, 3);
  Network &network = Network::getInstance(port, &blockchain, &blacklist);

// ───────────────────────────────────────────────────────────────
// 🧬 Load or Initialize Blockchain
// ───────────────────────────────────────────────────────────────
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

// ───────────────────────────────────────────────────────────────
// 📟 Interactive CLI Menu
// ───────────────────────────────────────────────────────────────
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
    // ────────────────────────────────────────
    // 🧾 Add Manual Transaction
    // ────────────────────────────────────────
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

      if (!tx.isValid(Crypto::toHex(dilKeys.publicKey), Crypto::toHex(falKeys.publicKey))) {
        std::cout << "Invalid transaction! Signature check failed.\n";
        break;
      }

      blockchain.addTransaction(tx);
      network.broadcastTransaction(tx);
      std::cout << "Transaction added & broadcasted!\n";
      break;
    }

    // ────────────────────────────────────────
    // ⛏️ Manual Single Block Mining
    // ────────────────────────────────────────
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
        blockchain.savePendingTransactionsToDB();
        network.broadcastBlock(minedBlock);
        blockchain.reloadBlockchainState();
        std::cout << "Block mined, saved, synced!\n";
      } else {
        std::cout << "Mining failed!\n";
      }
      break;
    }

    // ────────────────────────────────────────
    // 📜 Print Blockchain
    // ────────────────────────────────────────
    case 3:
      blockchain.printBlockchain();
      break;

    // ────────────────────────────────────────
    // 🔁 Start Mining Loop
    // ────────────────────────────────────────
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

    // ────────────────────────────────────────
    // 🔄 Sync With Peers
    // ────────────────────────────────────────
    case 5:
      std::cout << "Syncing with peers...\n";
      network.syncWithPeers();
      break;

    // ────────────────────────────────────────
    // 💰 Dev Fund Info
    // ────────────────────────────────────────
    case 6:
      std::cout << "\n=== Dev Fund Information ===\n";
      std::cout << "Address: DevFundWallet\n";
      std::cout << "Balance: " << blockchain.getBalance("DevFundWallet") << " AlynCoin\n";
      break;

    // ────────────────────────────────────────
    // ❌ Exit
    // ────────────────────────────────────────
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
