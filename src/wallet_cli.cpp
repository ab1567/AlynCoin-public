#include "wallet_cli.h"
#include <fstream>
#include <sstream>
#include "blockchain.h"

void WalletCLI::start() {
    std::cout << "=== Welcome to AlynCoin Wallet CLI ===" << std::endl;

    while (true) {
        std::cout << "\nOptions: \n";
        std::cout << "1. Create Wallet\n";
        std::cout << "2. Load Wallet\n";
        std::cout << "3. Check Balance\n";
        std::cout << "4. Send Coins\n";
        std::cout << "5. Exit\n";
        std::cout << "Enter choice: ";

        int choice;
        std::cin >> choice;

        switch (choice) {
            case 1: createWallet(); break;
            case 2: loadWallet(); break;
            case 3: checkBalance(); break;
            case 4: sendCoins(); break;
            case 5: std::cout << "Exiting...\n"; return;
            default: std::cout << "❌ Invalid choice! Try again.\n";
        }
    }
}

// 🔑 **Create a new wallet**
void WalletCLI::createWallet() {
    wallet = Wallet();
    wallet.saveToFile("wallet.json");
    std::cout << "✅ Wallet created! Address: " << wallet.getAddress() << std::endl;
}

// 🔄 **Load an existing wallet**
void WalletCLI::loadWallet() {
    try {
        wallet = Wallet::loadFromFile("wallet.json");
        std::cout << "✅ Wallet loaded! Address: " << wallet.getAddress() << std::endl;
    } catch (const std::exception& e) {
        std::cerr << e.what() << "\n";
    }
}

// 💰 **Check balance**
void WalletCLI::checkBalance() {
    try {
        std::cout << "🔎 Checking balance..." << std::endl;
        double balance = wallet.getBalance();
        std::cout << "💰 Balance: " << balance << " AlynCoins\n";
    } catch (const std::exception& e) {
        std::cerr << e.what() << "\n";
    }
}

// 💸 **Send Coins**
// ✅ **Send Coins with Smart Burn and RocksDB**
void WalletCLI::sendCoins() {
    std::string recipient;
    double amount;

    std::cout << "Enter recipient address: ";
    std::cin >> recipient;
    std::cout << "Enter amount: ";
    std::cin >> amount;

    try {
        Transaction tx = wallet.createTransaction(recipient, amount);
        Blockchain::getInstance().addTransaction(tx);
        tx.saveToDB(Blockchain::getInstance().getTransactionCount());

        std::cout << "✅ Transaction sent! TxID: " << tx.getHash() << std::endl;
    } catch (const std::exception& e) {
        std::cerr << e.what() << "\n";
    }
}

//
double Wallet::getBalance() const {
    return Blockchain::getInstance().getBalance(address);
}
