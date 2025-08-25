#include "wallet_cli.h"
#include "blockchain.h"
#include "mnemonic.h"
#include <fstream>
#include <sstream>
#include <limits>
#include <random>
#include <openssl/crypto.h>
#include <cstdio>

void WalletCLI::start() {
  std::cout << "=== Welcome to AlynCoin Wallet CLI ===" << std::endl;

  while (true) {
    std::cout << "\nOptions: \n";
    std::cout << "1. Create Wallet\n";
    std::cout << "2. Load Wallet\n";
    std::cout << "3. Check Balance\n";
    std::cout << "4. Send Coins\n";
    std::cout << "5. Exit\n";
    std::cout << "6. Show Wallet Public Keys\n";
    std::cout << "7. Generate New PQ Keys (Dilithium + Falcon)\n";
    std::cout << "8. Export Mnemonic Seed\n";
    std::cout << "9. Import Mnemonic Seed\n";
    std::cout << "Enter choice: ";

    int choice;
    std::cin >> choice;

    switch (choice) {
    case 1:
      createWallet();
      break;
    case 2:
      loadWallet();
      break;
    case 3:
      checkBalance();
      break;
    case 4:
      sendCoins();
      break;
    case 5:
      std::cout << "Exiting...\n";
      return;
    case 6:
      showKeys();
      break;
    case 7:
      generateNewPQKeys();
      break;
    case 8:
      exportSeed();
      break;
    case 9:
      importSeed();
      break;
    default:
      std::cout << "❌ Invalid choice! Try again.\n";
    }
  }
}

// 🔑 **Create a new wallet**
void WalletCLI::createWallet() {
  std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
  std::string passphrase;
  std::cout << "Enter a passphrase to secure your wallet: ";
  std::getline(std::cin, passphrase);
  wallet = Wallet("defaultWallet", WALLET_KEY_DIR, passphrase);
  std::cout << "✅ Wallet created! Address: " << wallet.getAddress()
            << std::endl;
}

// 🔄 **Load an existing wallet**
void WalletCLI::loadWallet() {
  std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
  std::string address, passphrase;
  std::cout << "Enter wallet address: ";
  std::getline(std::cin, address);
  std::cout << "Enter passphrase: ";
  std::getline(std::cin, passphrase);
  try {
    wallet = Wallet(address, WALLET_KEY_DIR, passphrase);
    std::cout << "✅ Wallet loaded! Address: " << wallet.getAddress()
              << std::endl;
  } catch (const std::exception &e) {
    std::cerr << e.what() << "\n";
  }
}
// 🟢 Show Public Keys
void WalletCLI::showKeys() {
  std::cout << "\n=== Wallet Keys ===\n";
  std::cout << "RSA Public Key:\n" << wallet.getPublicKey() << "\n";
  std::cout << "Dilithium Public Key:\n" << wallet.getDilithiumPublicKey()
            << "\n";
  std::cout << "Falcon Public Key:\n" << wallet.getFalconPublicKey() << "\n";
}

// 🟢 Generate Fresh PQ Keys
void WalletCLI::generateNewPQKeys() {
  wallet.generateDilithiumKeyPair();
  wallet.generateFalconKeyPair();
  std::cout << "✅ Dilithium & Falcon keys regenerated.\n";
}

void WalletCLI::exportSeed() {
  auto words = Mnemonic::generate();
  std::cout << "⚠️ Write down your seed phrase:\n";
  for (const auto &w : words) std::cout << w << ' ';
  std::cout << "\n";

  // Randomly pick two words for verification
  std::random_device rd; std::mt19937 gen(rd());
  std::uniform_int_distribution<> dist(0, static_cast<int>(words.size()) - 1);
  int i1 = dist(gen), i2; do { i2 = dist(gen); } while (i2 == i1);

  std::string ans1, ans2;
  std::cout << "Re-enter word #" << i1 + 1 << ": "; std::cin >> ans1;
  std::cout << "Re-enter word #" << i2 + 1 << ": "; std::cin >> ans2;
  if (ans1 != words[i1] || ans2 != words[i2]) {
    std::cout << "❌ Verification failed.\n";
    for (auto &w : words) OPENSSL_cleanse(w.data(), w.size());
    return;
  }

  // Build URI and show ASCII QR
  std::string uri = "alynseed:";
  for (size_t i = 0; i < words.size(); ++i) {
    if (i) uri += '-';
    uri += words[i];
  }
  std::string cmd = "qrencode -t ASCII \"" + uri + "\"";
  FILE *pipe = popen(cmd.c_str(), "r");
  if (pipe) {
    char buf[256];
    while (fgets(buf, sizeof(buf), pipe)) std::cout << buf;
    pclose(pipe);
  }
  std::cout << uri << "\n";

  for (auto &w : words) OPENSSL_cleanse(w.data(), w.size());
}

void WalletCLI::importSeed() {
  std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
  std::cout << "Enter seed words separated by space:\n";
  std::string line; std::getline(std::cin, line);
  std::istringstream iss(line);
  std::vector<std::string> words; std::string w; while (iss>>w) words.push_back(w);
  if(!Mnemonic::validate(words)){
    std::cout << "❌ Invalid mnemonic\n";
    return;
  }
  auto seed = Mnemonic::mnemonicToSeed(words);
  std::cout << "✅ Seed imported (" << seed.size() << " bytes).\n";
  std::fill(seed.begin(), seed.end(), 0);
  for (auto &s : words) OPENSSL_cleanse(s.data(), s.size());
}

// 💰 **Check balance**
void WalletCLI::checkBalance() {
  try {
    std::cout << "🔎 Checking balance..." << std::endl;
    double balance = wallet.getBalance();
    std::cout << "💰 Balance: " << balance << " AlynCoins\n";
  } catch (const std::exception &e) {
    std::cerr << e.what() << "\n";
  }
}

// 💸 **Send Coins**
void WalletCLI::sendCoins() {
  std::string recipient;
  double amount;
  int sigChoice;

  std::cout << "Enter recipient address: ";
  std::cin >> recipient;
  std::cout << "Enter amount: ";
  std::cin >> amount;
  std::cout << "Choose Signature Scheme:\n";
  std::cout << "1. Dilithium\n2. Falcon\n3. Both (Hybrid)\nChoice: ";
  std::cin >> sigChoice;

  try {
    Transaction tx = wallet.createTransaction(recipient, amount);

    // You can store user preference inside tx or print info here
    if (sigChoice == 1) {
      std::cout << "📝 Using Dilithium signature.\n";
    } else if (sigChoice == 2) {
      std::cout << "📝 Using Falcon signature.\n";
    } else {
      std::cout << "📝 Using Hybrid (Dilithium + Falcon) signature.\n";
    }

    auto &blockchain =
        Blockchain::getInstance(8333, DBPaths::getBlockchainDB(), false);
    blockchain.addTransaction(tx);
    Transaction::saveToDB(tx, blockchain.getRecentTransactionCount());
    std::cout << "✅ Transaction sent! TxID: " << tx.getHash() << std::endl;
  } catch (const std::exception &e) {
    std::cerr << e.what() << "\n";
  }
}

int main() {
  WalletCLI cli;
  cli.start();
  return 0;
}
