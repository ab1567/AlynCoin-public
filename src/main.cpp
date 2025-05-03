#include "blockchain.h"
#include "crypto_utils.h"
#include "miner.h"
#include "network.h"
#include "self_healing/self_healing_node.h"
#include "network/peer_blacklist.h"
#include "db/db_paths.h"

#include <chrono>
#include <iostream>
#include <limits>
#include <thread>
#include <filesystem>

void clearInputBuffer() {
    std::cin.clear();
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
}

unsigned short getPortFromArgsOrDefault(int argc, char *argv[]) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--port" && i + 1 < argc) {
            return static_cast<unsigned short>(std::stoi(argv[i + 1]));
        }
    }
    return 8333;
}

int main(int argc, char *argv[]) {
    unsigned short port = DEFAULT_PORT;
    std::string dbPath = DBPaths::getBlockchainDB();
    std::string connectIP = "";
    std::string walletAddress = "default_wallet";
    std::string keyDir = DBPaths::getKeyPath(walletAddress);

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
        }
    }

    // ✅ Fix: Use node-specific blacklist directory
    std::string blacklistPath = dbPath + "/blacklist";
    std::filesystem::create_directories(blacklistPath);

    Blockchain &blockchain = Blockchain::getInstance(port, dbPath, false);
    PeerBlacklist blacklist(blacklistPath, 3);
    Network &network = Network::getInstance(port, &blockchain, &blacklist);

    blockchain.loadFromDB();
    blockchain.reloadBlockchainState();

    // ✅ Full duplex peer connection logic
    if (!connectIP.empty()) {
        std::string ip;
        short connectPort;

        if (connectIP.find(":") != std::string::npos) {
            size_t colon = connectIP.find(":");
            ip = connectIP.substr(0, colon);
            connectPort = std::stoi(connectIP.substr(colon + 1));
        } else {
            ip = connectIP;
            connectPort = 8333;
        }

        network.connectToPeer(ip, connectPort);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        network.connectToPeer("127.0.0.1", port);
    }

    network.syncWithPeers();
    std::this_thread::sleep_for(std::chrono::seconds(2));

    PeerManager *peerManager = network.getPeerManager();
    SelfHealingNode healer(&blockchain, peerManager);

    std::thread autoHealThread([&]() {
        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(30));
            std::cout << "\n🩺 [Auto-Heal] Running periodic health monitor...\n";
            healer.monitorAndHeal();
        }
    });
    autoHealThread.detach();

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
        std::cout << "8. Run Self-Heal Now 🩺\n";
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
                std::cout << "Enter recipient: ";
                std::cin >> recipient;
                std::cout << "Enter amount: ";
                std::cin >> amount;

                Crypto::ensureUserKeys(sender);
                DilithiumKeyPair dilKeys = Crypto::loadDilithiumKeys(sender);
                FalconKeyPair falKeys = Crypto::loadFalconKeys(sender);

                Transaction tx(sender, recipient, amount, "", "", time(nullptr));
                tx.signTransaction(dilKeys.privateKey, falKeys.privateKey);

                if (!tx.isValid(Crypto::toHex(dilKeys.publicKey), Crypto::toHex(falKeys.publicKey))) {
                    std::cout << "❌ Invalid transaction (signature check failed).\n";
                    break;
                }

                blockchain.addTransaction(tx);
                network.broadcastTransaction(tx);
                std::cout << "✅ Transaction added and broadcasted.\n";
                break;
            }

            case 2: {
                std::cout << "Enter miner address: ";
                std::cin >> minerAddress;
                Block mined = blockchain.mineBlock(minerAddress);
                if (!mined.getHash().empty()) {
                    blockchain.saveToDB();
                    blockchain.savePendingTransactionsToDB();
                    network.broadcastBlock(mined);
                    blockchain.reloadBlockchainState();
                    std::cout << "✅ Block mined and broadcasted.\n";
                }
                break;
            }

            case 3:
                blockchain.printBlockchain();
                break;

            case 4:
                std::cout << "Enter miner address: ";
                std::cin >> minerAddress;
                Miner::startMiningProcess(minerAddress);
                break;

            case 5:
                network.intelligentSync();
                break;

            case 6:
                std::cout << "Dev Fund Balance: " << blockchain.getBalance("DevFundWallet") << " AlynCoin\n";
                break;

            case 7:
                std::cout << "Shutting down AlynCoin Node...\n";
                running = false;
                break;

            case 8:
                std::cout << "🩺 Manually triggering self-healing check...\n";
                healer.monitorAndHeal();
                break;

            default:
                std::cout << "Invalid choice!\n";
        }
    }

    return 0;
}

