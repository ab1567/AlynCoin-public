#ifndef WALLET_CLI_H
#define WALLET_CLI_H

#include "wallet.h"
#include <iostream>
#include <string>

class WalletCLI {
public:
  void start();

private:
  Wallet wallet;

  void createWallet();
  void loadWallet();
  void checkBalance();
  void sendCoins();
  void generateNewPQKeys();
  void showKeys();
};

#endif // WALLET_CLI_H
