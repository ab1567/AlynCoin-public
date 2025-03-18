#include <iostream>
#include <limits>
#include <string>
#include <fstream>
#include "wallet.h"
#include "network.h"
#include "blockchain.h"
#include "crypto_utils.h"
#include <json/json.h>

// Print CLI Menu
void printMenu() {
    std::cout << "\n=== 🏦 AlynCoin Wallet CLI ===\n";
    std::cout << "1️⃣  Generate new wallet\n";
    std::cout << "2️⃣  Load existing wallet\n";
    std::cout << "3️⃣  Check balance\n";
    std::cout << "4️⃣  Send transaction\n";
    std::cout << "5️⃣  Mine block\n";
    std::cout << "6️⃣  Print blockchain\n";
    std::cout << "7️⃣  View Dev Fund Info\n";
    std::cout << "8️⃣  Exit\n";
    std::cout << "🔋 Choose an option: ";
}

int cliMain(int argc, char* argv[]) {
    unsigned short port = 8333;
    std::string dbPath = "";
    std::string connectPeer = "";
    std::string keyDir = "/root/.alyncoin/keys/";  // Default key path

    // Argument parsing
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--dbpath" && i + 1 < argc) {
            dbPath = argv[++i];
        } else if (arg == "--connect" && i + 1 < argc) {
            connectPeer = argv[++i];
        } else if (arg == "--keypath" && i + 1 < argc) {
            keyDir = argv[++i];
            if (keyDir.back() != '/') keyDir += '/';
            std::cout << "🔑 Using custom key directory: " << keyDir << std::endl;
        } else {
            try {
                port = std::stoi(arg);
                std::cout << "🌐 Using custom port: " << port << std::endl;
            } catch (...) {
                std::cerr << "⚠️ Unknown argument: " << arg << "\n";
            }
        }
    }

    Wallet* wallet = nullptr;
    Blockchain& blockchain = Blockchain::getInstance(port, dbPath);
    Network& network = Network::getInstance(port, &blockchain);

    // Attempt connection if specified
    if (!connectPeer.empty()) {
        size_t colonPos = connectPeer.find(':');
        if (colonPos != std::string::npos) {
            std::string ip = connectPeer.substr(0, colonPos);
            int peerPort = std::stoi(connectPeer.substr(colonPos + 1));
            if (!network.connectToNode(ip, peerPort)) {
                std::cerr << "❌ Failed to connect to AlynCoin node at " << connectPeer << "\n";
            } else {
                std::cout << "✅ Connected to AlynCoin Node at " << connectPeer << "\n";
            }
        }
    }

    // CLI Loop
    bool running = true;
    while (running) {
        printMenu();
        int choice;
        std::cin >> choice;

        if (std::cin.fail()) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cout << "❌ Invalid input. Please enter a valid option.\n";
            continue;
        }

        switch (choice) {
            case 1:
                if (wallet) delete wallet;
                wallet = new Wallet();
                std::cout << "✅ New wallet created!\n";
                std::cout << "🔑 Address: " << wallet->getAddress() << std::endl;
                break;

            case 2: {
                std::string privateKeyPath;
                std::cout << "Enter private key file path: ";
                std::cin >> privateKeyPath;

                std::ifstream keyFile(privateKeyPath);
                if (!keyFile) {
                    std::cout << "❌ Error: Private key file not found!\n";
                    break;
                }

                if (wallet) delete wallet;
                wallet = new Wallet(privateKeyPath);
                std::cout << "✅ Wallet loaded successfully!\n";
                std::cout << "🔑 Address: " << wallet->getAddress() << std::endl;
                break;
            }

            case 3:
                if (!wallet) {
                    std::cout << "❌ Load a wallet first!\n";
                    break;
                }
                std::cout << "🔍 Checking balance for: " << wallet->getAddress() << std::endl;
                std::cout << "💰 Balance: " << blockchain.getBalance(wallet->getAddress()) << " AlynCoin\n";
                break;

            case 4: {
                if (!wallet) {
                    std::cout << "❌ Load a wallet first!\n";
                    break;
                }

                std::string recipient;
                double amount;
                std::cout << "Enter recipient address: ";
                std::cin >> recipient;
                std::cout << "Enter amount: ";
                std::cin >> amount;

                if (amount <= 0) {
                    std::cout << "❌ Invalid amount! Must be greater than zero.\n";
                    break;
                }

                std::string sender = wallet->getAddress();
                if (sender == "DevFundWallet") {
                    std::cout << "❌ Transactions from DevFundWallet are restricted.\n";
                    break;
                }

                Crypto::ensureUserKeys(sender);

                Transaction tx(sender, recipient, amount, "");
                tx.signTransaction(getPrivateKeyPath(sender));

                if (!tx.isValid("")) {
                    std::cout << "❌ Invalid transaction! Signature verification failed.\n";
                    break;
                }

                std::cout << "✅ Transaction created & signed!\n";
                network.broadcastTransaction(tx);
                std::cout << "📡 Transaction broadcasted!\n";
                break;
            }

            case 5: {
                if (!wallet) {
                    std::cout << "❌ Load a wallet first!\n";
                    break;
                }

                std::string minerAddress = wallet->getAddress();
                std::cout << "⛏️  Starting mining with address: " << minerAddress << std::endl;

                blockchain.mineBlock(minerAddress);
                blockchain.saveToDB();

                std::cout << "✅ Latest Block Hash: " << blockchain.getLatestBlock().getHash() << std::endl;
                break;
            }

            case 6: {
                std::cout << "=== AlynCoin Blockchain ===\n";
                Json::StreamWriterBuilder writer;
                writer["indentation"] = "    ";
                std::string formattedJson = Json::writeString(writer, blockchain.toJSON());
                std::cout << formattedJson << std::endl;
                break;
            }

            case 7: {
                std::cout << "\n=== 💼 Dev Fund Information ===\n";
                std::cout << "🏦 Address: DevFundWallet\n";
                std::cout << "💰 Balance: " << blockchain.getBalance("DevFundWallet") << " AlynCoin\n";
                break;
            }

            case 8:
                running = false;
                break;

            default:
                std::cout << "❌ Invalid choice! Please select a valid option.\n";
        }
   
::contentReference[oaicite:0]{index=0}
 
