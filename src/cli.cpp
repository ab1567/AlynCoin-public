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
#include "db/db_paths.h"
#include "governance/dao.h"
#include "governance/devfund.h"
#include "governance/dao_storage.h"

void printMenu() {
  std::cout << "\n=== AlynCoin Wallet CLI ===\n";
  std::cout << "1. Generate new wallet\n";
  std::cout << "2. Load existing wallet\n";
  std::cout << "3. Check balance\n";
  std::cout << "4. Send L1 transaction\n";
  std::cout << "5. Send L2 transaction\n";
  std::cout << "6. Mine block\n";
  std::cout << "7. Print blockchain\n";
  std::cout << "8. View Dev Fund Info\n";
  std::cout << "9. Manage Peer Blacklist\n";
  std::cout << "10. Generate Rollup Block (zk-STARK)\n";
  std::cout << "11. Exit\n";
  std::cout << "12. Submit DAO Proposal\n";
  std::cout << "13. Vote on DAO Proposal\n";
  std::cout << "14. View DAO Proposals\n";
  std::cout << "15. Finalize DAO Proposal\n";
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

int cliMain(int argc, char *argv[]);

int main(int argc, char **argv) {
  if (argc >= 3) {
    std::string cmd = argv[1];
    std::string arg1 = argv[2];
    std::string keyDir = "/root/.alyncoin/keys/";

    if (cmd == "createwallet") {
      Wallet *wallet = nullptr;
      try {
        wallet = new Wallet(arg1, keyDir);
        std::cout << "✅ Wallet created: " << wallet->getAddress() << std::endl;
      } catch (const std::exception &e) {
        std::cerr << "❌ Wallet creation failed: " << e.what() << std::endl;
      }
      delete wallet;
      return 0;
    }

    if (cmd == "loadwallet") {
      std::string privPath = keyDir + arg1 + "_private.pem";
      std::string dilPath = keyDir + arg1 + "_dilithium.key";
      std::string falPath = keyDir + arg1 + "_falcon.key";

      if (!std::filesystem::exists(privPath) || !std::filesystem::exists(dilPath) || !std::filesystem::exists(falPath)) {
        std::cerr << "❌ Wallet key files not found for: " << arg1 << std::endl;
        return 1;
      }

      Wallet *wallet = nullptr;
      try {
        wallet = new Wallet(privPath, keyDir, arg1);
        std::cout << "✅ Wallet loaded successfully: " << wallet->getAddress() << std::endl;
        std::ofstream("/root/.alyncoin/current_wallet.txt") << wallet->getAddress();
      } catch (const std::exception &e) {
        std::cerr << "❌ Wallet loading failed: " << e.what() << std::endl;
        return 1;
      }
      delete wallet;
      return 0;
    }

    if (cmd == "send" && argc >= 4) {
      Blockchain &blockchain = Blockchain::getInstance(8333, DBPaths::getBlockchainDB());
      std::string recipient = arg1;
      double amount = std::stod(argv[3]);
      bool isL2 = (argc >= 5 && std::string(argv[4]) == "--l2");

      std::ifstream in(keyDir + "current_wallet.txt");
      std::string sender;
      std::getline(in, sender);

      if (sender.empty()) {
        std::cerr << "❌ No active wallet loaded. Please load one first.\n";
        return 1;
      }

      auto dilPriv = Crypto::loadDilithiumKeys(sender);
      auto falPriv = Crypto::loadFalconKeys(sender);

      Transaction tx(sender, recipient, amount, "", "", time(nullptr));
      if (isL2) tx.setMetadata("L2");
      tx.signTransaction(dilPriv.privateKey, falPriv.privateKey);

      if (!tx.getSignatureDilithium().empty() && !tx.getSignatureFalcon().empty()) {
        blockchain.addTransaction(tx);
        Network::getInstance(8333, &blockchain).broadcastTransaction(tx);
        std::cout << "✅ Transaction sent: " << amount << " AlynCoin to " << recipient << std::endl;
      } else {
        std::cerr << "❌ Signature failure.\n";
        return 1;
      }

      return 0;
    }
  }

  return cliMain(argc, argv);
}

int cliMain(int argc, char *argv[]) {
  unsigned short port = 8333;
  std::string dbPath = DBPaths::getBlockchainDB();
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

    case 4: {  // 🔁 Send L1 Transaction
      if (!wallet) {
        std::cout << "❌ Load or create a wallet first!\n";
        break;
      }

      std::string recipient;
      double amount;
      std::cout << "Enter recipient address: ";
      std::cin >> recipient;
      std::cout << "Enter amount: ";
      std::cin >> amount;

      if (recipient.empty() || amount <= 0) {
        std::cout << "❌ Invalid input. Address must not be empty and amount must be positive.\n";
        break;
      }

      std::string sender = wallet->getAddress();
      auto dilPriv = Crypto::loadDilithiumKeys(sender);
      auto falPriv = Crypto::loadFalconKeys(sender);

      Transaction tx(sender, recipient, amount, "", "", time(nullptr));
      std::cout << "[DEBUG] signTransaction() called for sender: " << sender << "\n";
      tx.signTransaction(dilPriv.privateKey, falPriv.privateKey);

      if (!tx.getSignatureDilithium().empty() && !tx.getSignatureFalcon().empty()) {
        blockchain.addTransaction(tx);
        std::cout << "📦 [DEBUG] Saving pending transactions to RocksDB...\n";
        blockchain.savePendingTransactionsToDB();  // <-- this ensures RocksDB write
        network.broadcastTransaction(tx);
        std::cout << "✅ Transactions successfully saved to RocksDB.\n";
        std::cout << "✅ Transaction created and broadcasted!\n";
      } else {
        std::cerr << "❌ Signature failure. Transaction not broadcasted.\n";
      }

      break;
    }

    case 5: {  // 🔁 Send L2 Transaction
      if (!wallet) {
        std::cout << "❌ Load or create a wallet first!\n";
        break;
      }

      std::string recipient;
      double amount;
      std::cout << "Enter recipient address (L2): ";
      std::cin >> recipient;
      std::cout << "Enter amount: ";
      std::cin >> amount;

      if (recipient.empty() || amount <= 0) {
        std::cout << "❌ Invalid input. Address must not be empty and amount must be positive.\n";
        break;
      }

      std::string sender = wallet->getAddress();
      auto dilPriv = Crypto::loadDilithiumKeys(sender);
      auto falPriv = Crypto::loadFalconKeys(sender);

      Transaction tx(sender, recipient, amount, "", "", time(nullptr));
      tx.setMetadata("L2");
      std::cout << "[DEBUG] signTransaction() called for sender: " << sender << "\n";
      tx.signTransaction(dilPriv.privateKey, falPriv.privateKey);

      if (!tx.getSignatureDilithium().empty() && !tx.getSignatureFalcon().empty()) {
        blockchain.addTransaction(tx);
        std::cout << "📦 [DEBUG] Saving pending transactions to RocksDB...\n";
        blockchain.savePendingTransactionsToDB();  // <-- persists the pool
        network.broadcastTransaction(tx);
        std::cout << "✅ Transactions successfully saved to RocksDB.\n";
        std::cout << "✅ L2 Transaction created and broadcasted!\n";
      } else {
        std::cerr << "❌ Signature failure. L2 Transaction not broadcasted.\n";
      }

      break;
    }

    case 6: {
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

    case 7:
      std::cout << "=== AlynCoin Blockchain ===\n";
      std::cout << Json::writeString(Json::StreamWriterBuilder(), blockchain.toJSON()) << std::endl;
      break;

    case 8:
      std::cout << "\n=== Dev Fund Information ===\n";
      std::cout << "Address: DevFundWallet\n";
      std::cout << "Balance: " << blockchain.getBalance("DevFundWallet") << " AlynCoin\n";
      break;

    case 9: {
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

    case 10: {
        if (!wallet) {
            std::cout << "Load or create a wallet first!\n";
            break;
        }

        // 🔍 Snapshot current L1 state
        std::unordered_map<std::string, double> stateBefore = blockchain.getCurrentState();

        // 📦 Fetch L2 transactions
        std::vector<Transaction> l2Transactions = blockchain.getPendingL2Transactions();

        // 🧮 Simulate L2 state update
        std::unordered_map<std::string, double> stateAfter =
            blockchain.simulateL2StateUpdate(stateBefore, l2Transactions);

        // 🧱 Create Rollup Block
        RollupBlock rollup(
            blockchain.getRollupChainSize(),               // Index
            blockchain.getLastRollupHash(),                // Previous Hash
            l2Transactions                                  // L2 Transactions
        );

        std::string prevRecursive = blockchain.getLastRollupProof(); // Recursive input

        // 🔐 Generate zk-STARK proof + recursive proof
        rollup.generateRollupProof(stateBefore, stateAfter, prevRecursive);

        // ➕ Add to rollup chain
     if (blockchain.isRollupBlockValid(rollup)) {
        blockchain.addRollupBlock(rollup);
        std::cout << "✅ Rollup Block created successfully!\n";
        std::cout << "📦 Rollup Hash: " << rollup.getHash() << "\n";
       } else {
        std::cerr << "❌ Rollup Block creation failed: Proof invalid.\n";
    }

        std::cout << "📦 Rollup Hash: " << rollup.getHash() << "\n";
        break;
    }

    case 11: running = false; break;

   case 12: {
    if (!wallet) {
        std::cout << "Load or create a wallet first!\n";
        break;
    }

    Proposal proposal;
    proposal.proposal_id = Crypto::sha256(Crypto::generateRandomHex(16));
    proposal.proposer_address = wallet->getAddress();

    std::cin.ignore();
    std::cout << "Enter proposal description: ";
    std::getline(std::cin, proposal.description);

    std::cout << "Select Proposal Type:\n"
              << "1. Protocol Upgrade\n"
              << "2. Fund Allocation\n"
              << "3. Blacklist Appeal\n"
              << "4. Custom Action\n"
              << "Choice: ";
    int typeChoice;
    std::cin >> typeChoice;
    proposal.type = static_cast<ProposalType>(typeChoice - 1);

    // Handle FUND_ALLOCATION-specific input
    if (proposal.type == ProposalType::FUND_ALLOCATION) {
        std::cout << "Enter amount to transfer from Dev Fund: ";
        std::cin >> proposal.transfer_amount;

        std::cout << "Enter recipient address: ";
        std::cin.ignore(); // flush newline
        std::getline(std::cin, proposal.target_address);

        if (proposal.transfer_amount <= 0 || proposal.target_address.empty()) {
            std::cerr << "❌ Invalid fund allocation details.\n";
            break;
        }
    }

    proposal.yes_votes = 0;
    proposal.no_votes = 0;
    proposal.creation_time = std::time(nullptr);
    proposal.deadline_time = proposal.creation_time + 86400;  // 24 hours
    proposal.status = ProposalStatus::PENDING;

    if (DAO::createProposal(proposal)) {
        std::cout << "✅ Proposal submitted. ID: " << proposal.proposal_id << "\n";
    } else {
        std::cerr << "❌ Failed to submit proposal.\n";
    }

    break;
}

   case 13: {
    if (!wallet) {
        std::cout << "Load or create a wallet first!\n";
        break;
    }

    std::string proposal_id;
    std::cout << "Enter Proposal ID: ";
    std::cin >> proposal_id;

    std::string voteStr;
    std::cout << "Vote YES or NO: ";
    std::cin >> voteStr;

    bool voteYes = (voteStr == "YES" || voteStr == "yes" || voteStr == "Y" || voteStr == "y");
    uint64_t weight = static_cast<uint64_t>(blockchain.getBalance(wallet->getAddress()));

    if (weight == 0) {
        std::cerr << "⚠️ You have no voting weight (0 balance).\n";
        break;
    }

    if (DAO::castVote(proposal_id, voteYes, weight)) {
        std::cout << "✅ Vote cast successfully! Weight: " << weight << "\n";
    } else {
        std::cerr << "❌ Failed to cast vote.\n";
    }

    break;
  }
    case 14: {
        std::vector<Proposal> proposals = DAOStorage::getAllProposals();
        std::cout << "\n=== DAO Proposals ===\n";
        for (const auto& p : proposals) {
            std::cout << "📜 ID: " << p.proposal_id << "\n";
            std::cout << "📝 Description: " << p.description << "\n";
            std::cout << "🧭 Type: " << static_cast<int>(p.type) << "\n";
            std::cout << "📅 Deadline: " << p.deadline_time << "\n";
            std::cout << "✅ YES: " << p.yes_votes << " | ❌ NO: " << p.no_votes << "\n";
            std::cout << "📌 Status: " << static_cast<int>(p.status) << "\n\n";
        }
        break;
    }

    case 15: {
        std::string pid;
        std::cout << "Enter Proposal ID to finalize: ";
        std::cin >> pid;
        if (DAO::finalizeProposal(pid)) {
            std::cout << "✅ Proposal finalized.\n";
        } else {
            std::cerr << "❌ Failed to finalize proposal.\n";
        }
        break;
    }

    default: std::cout << "Invalid choice! Please select a valid option.\n";
    }
  }


  if (wallet) delete wallet;
  return 0;
}

