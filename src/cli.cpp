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
#include <ctime>
#include <filesystem>
#include "db/db_instance.h"

std::string getCurrentWallet() {
    std::ifstream in("/root/.alyncoin/current_wallet.txt");
    std::string addr;
    std::getline(in, addr);
    return addr;
}

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
  std::cout << "16. View Blockchain Stats\n";
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
    std::ios::sync_with_stdio(true);
    std::cout.setf(std::ios::unitbuf);
    std::string keyDir = "/root/.alyncoin/keys/";

    bool skipDB = false;
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--nodb") {
            skipDB = true;
            for (int j = i; j < argc - 1; ++j) argv[j] = argv[j + 1];
            --argc;
            break;
        }
    }

    // === DAO viewer ===
    if (argc == 2 && std::string(argv[1]) == "dao-view") {
        auto proposals = DAOStorage::getAllProposals();
        std::cout << "\n=== DAO Proposals ===\n";
        for (const auto &p : proposals) {
            std::cout << "📜 ID: " << p.proposal_id << "\n";
            std::cout << "📝 Description: " << p.description << "\n";
            std::cout << "🛍 Type: " << static_cast<int>(p.type) << "\n";
            std::cout << "📅 Deadline: " << p.deadline_time << "\n";
            std::cout << "✅ YES: " << p.yes_votes << " | ❌ NO: " << p.no_votes << "\n";
            std::cout << "📌 Status: " << static_cast<int>(p.status) << "\n\n";
        }
        std::exit(0);
    }

    // === Blockchain stats ===
    if (argc >= 2 && std::string(argv[1]) == "stats") {
        bool skipNet = false;
        for (int i = 2; i < argc; ++i)
            if (std::string(argv[i]) == "--nonetwork") skipNet = true;

        if (skipNet) {
            Blockchain &b = Blockchain::getInstanceNoNetwork();
            std::cout << "\n=== Blockchain Stats ===\n";
            std::cout << "Total Blocks: " << b.getBlockCount() << "\n";
            std::cout << "Difficulty: " << DIFFICULTY << "\n";
            std::cout << "Total Supply: " << b.getTotalSupply() << " AlynCoin\n";
            std::cout << "Total Burned Supply: " << b.getTotalBurnedSupply() << " AlynCoin\n";
            std::cout << "Dev Fund Balance: " << b.getBalance("DevFundWallet") << " AlynCoin\n";
            std::exit(0);
        } else {
            std::cerr << "❌ Error: 'stats' must be used with --nonetwork flag.\n";
            return 1;
        }
    }
    // Only initialize RocksDB if not skipped
    if (!skipDB) {
        DB::getInstance();
    }

    // === Wallet creation ===
    if (argc == 3 && std::string(argv[1]) == "createwallet") {
        try {
            Wallet w(argv[2], keyDir);
            std::cout << "✅ Wallet created: " << w.getAddress() << "\n";
        } catch (const std::exception &e) {
            std::cerr << "❌ Wallet creation failed: " << e.what() << "\n";
            return 1;
        }
        std::exit(0);
    }

    // === Wallet loading ===
    if (argc == 3 && std::string(argv[1]) == "loadwallet") {
        std::string name = argv[2];
        std::string priv = keyDir + name + "_private.pem";
        std::string dil = keyDir + name + "_dilithium.key";
        std::string fal = keyDir + name + "_falcon.key";

        if (!std::filesystem::exists(priv) || !std::filesystem::exists(dil) || !std::filesystem::exists(fal)) {
            std::cerr << "❌ Wallet key files not found for: " << name << "\n";
            return 1;
        }

        try {
            Wallet w(priv, keyDir, name);
            std::ofstream("/root/.alyncoin/current_wallet.txt") << w.getAddress();
            std::cout << "✅ Wallet loaded: " << w.getAddress() << "\n";
        } catch (const std::exception &e) {
            std::cerr << "❌ Wallet load failed: " << e.what() << "\n";
            return 1;
        }
        std::exit(0);
    }

    // === Balance check ===
    if (argc >= 3 && std::string(argv[1]) == "balance") {
        std::string addr = argv[2];
        bool skipNet = false;
        for (int i = 3; i < argc; ++i)
            if (std::string(argv[i]) == "--nonetwork") skipNet = true;

        if (skipNet) {
            Blockchain &b = Blockchain::getInstanceNoNetwork();
            std::cout << "✅ Balance for " << addr << ": " << b.getBalance(addr) << " AlynCoin\n";
            std::exit(0);
        }
    }

    // === sendl1 / sendl2 (5 or 6 args) ===
   if ((argc >= 5) && (std::string(argv[1]) == "sendl1" || std::string(argv[1]) == "sendl2")) {
     std::string from, to = "metadataSink", metadata;
     double amount = 0.0;
     bool skipNet = false;
     int cmdIndex = 2;

     while (cmdIndex < argc) {
         std::string arg = argv[cmdIndex];
         if (arg == "--nonetwork") {
             skipNet = true;
             ++cmdIndex;
         } else break;
     }

     if (argc - cmdIndex == 3) {
         from = argv[cmdIndex++];
         amount = std::stod(argv[cmdIndex++]);
         metadata = argv[cmdIndex++];
     } else if (argc - cmdIndex == 4) {
         from = argv[cmdIndex++];
         to = argv[cmdIndex++];
         amount = std::stod(argv[cmdIndex++]);
         metadata = argv[cmdIndex++];
     } else {
         std::cerr << "❌ Invalid arguments for sendl1/sendl2\n";
         return 1;
     }

     Blockchain &b = skipNet ? Blockchain::getInstanceNoNetwork() : Blockchain::getInstance();
     auto dil = Crypto::loadDilithiumKeys(from);
     auto fal = Crypto::loadFalconKeys(from);

     Transaction tx(from, to, amount, "", metadata, time(nullptr));
     if (std::string(argv[1]) == "sendl2") tx.setMetadata("L2:" + metadata);

     tx.signTransaction(dil.privateKey, fal.privateKey);
     if (!tx.getSignatureDilithium().empty() && !tx.getSignatureFalcon().empty()) {
         b.addTransaction(tx);
         b.savePendingTransactionsToDB();
         std::cout << "✅ Transaction broadcasted: " << from << " → " << to
                   << " (" << amount << " AlynCoin, metadata: " << metadata << ")\n";
     } else {
         std::cerr << "❌ Transaction signing failed.\n";
         return 1;
     }
     std::exit(0);
   }

    // === DAO submit ===
    if (argc >= 4 && std::string(argv[1]) == "dao-submit") {
        std::string from = argv[2];
        std::string desc = argv[3];
        ProposalType type = ProposalType::CUSTOM_ACTION;
        double amt = (argc >= 6) ? std::stod(argv[5]) : 0.0;
        std::string target = (argc >= 7) ? argv[6] : "";
        if (argc >= 5) type = static_cast<ProposalType>(std::stoi(argv[4]));

        Proposal prop;
        prop.proposal_id = Crypto::sha256(Crypto::generateRandomHex(16));
        prop.proposer_address = from;
        prop.description = desc;
        prop.type = type;
        prop.transfer_amount = amt;
        prop.target_address = target;
        prop.creation_time = std::time(nullptr);
        prop.deadline_time = prop.creation_time + 86400;
        prop.status = ProposalStatus::PENDING;

        if (DAO::createProposal(prop)) {
            std::cout << "✅ Proposal submitted. ID: " << prop.proposal_id << "\n";
        } else {
            std::cerr << "❌ Failed to submit proposal.\n";
        }
        std::exit(0);
    }

    // === DAO vote ===
    if (argc >= 5 && std::string(argv[1]) == "dao-vote") {
        std::string from = argv[2];
        std::string propID = argv[3];
        std::string vote = argv[4];

        bool yes = (vote == "yes" || vote == "y");
        double weight = Blockchain::getInstanceNoNetwork().getBalance(from);
        if (DAO::castVote(propID, yes, static_cast<uint64_t>(weight))) {
            std::cout << "✅ Vote cast!\n";
        } else {
            std::cerr << "❌ Failed to vote.\n";
        }
        std::exit(0);
    }

    // === My chain stats ===
    if (argc == 3 && std::string(argv[1]) == "mychain") {
        std::string addr = argv[2];
        Blockchain &b = Blockchain::getInstanceNoNetwork();
        int count = 0;
        double reward = 0.0;

        for (const auto &blk : b.getAllBlocks()) {
            if (blk.getMinerAddress() == addr) {
                count++;
                reward += blk.getReward();
            }
        }

        std::cout << "📦 Blocks mined: " << count << "\n";
        std::cout << "💰 Total rewards: " << reward << " AlynCoin\n";
        std::exit(0);
    }

     // Prevent re-entry if known command was processed (after skipping flags)
       int cmdIndex = 1;
	while (cmdIndex < argc && std::string(argv[cmdIndex]).rfind("--", 0) == 0) {
    	cmdIndex++;
	}

	if (cmdIndex < argc) {
    	std::string cmd = argv[cmdIndex];
    	bool known = (cmd == "sendl1" || cmd == "sendl2" || cmd == "createwallet" ||
                  cmd == "loadwallet" || cmd == "balance" || cmd == "dao-view" ||
                  cmd == "dao-submit" || cmd == "dao-vote" || cmd == "mychain" ||
                  cmd == "stats");

    	if (!known) {
        std::cerr << "❌ Unknown or unsupported command: " << cmd << "\n";
        return 1;
    	}

    	std::exit(0);
}

    // === Fallback to interactive CLI menu ===
    return cliMain(argc, argv);
}


int cliMain(int argc, char *argv[]) {
  unsigned short port = 8333;
  std::string dbPath = DBPaths::getBlockchainDB();
  std::string connectPeer = "";
  std::string keyDir = "/root/.alyncoin/keys/";
  std::string blacklistPath = "/root/.alyncoin/blacklist";
  bool skipNetwork = false;

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
     } else if (arg == "--nonetwork") {
        skipNetwork = true;
        std::cout << "⚙️  Network disabled via --nonetwork flag.\n";

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

  Network *network = nullptr;
  if (!skipNetwork) {
  network = &Network::getInstance(port, &blockchain, &peerBlacklist);
  }

  if (!connectPeer.empty()) {
    size_t colonPos = connectPeer.find(':');
    if (colonPos != std::string::npos) {
      std::string ip = connectPeer.substr(0, colonPos);
      int peerPort = std::stoi(connectPeer.substr(colonPos + 1));
      if (!network->connectToNode(ip, peerPort)) {
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
        if (network) network->broadcastTransaction(tx);
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
        if (network) network->broadcastTransaction(tx);
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

    case 16: {
        std::cout << "\n=== Blockchain Stats ===\n";
        std::cout << "Total Blocks: " << blockchain.getBlockCount() << "\n";
        std::cout << "Difficulty: " << DIFFICULTY << "\n";
        std::cout << "Total Supply: " << totalSupply << " AlynCoin\n";
        std::cout << "Total Burned Supply: " << blockchain.getTotalBurnedSupply() << " AlynCoin\n";
        std::cout << "Dev Fund Balance: " << blockchain.getBalance("DevFundWallet") << " AlynCoin\n";
        break;
    }

    default: std::cout << "Invalid choice! Please select a valid option.\n";
    }
  }


  if (wallet) delete wallet;
  return 0;
}

