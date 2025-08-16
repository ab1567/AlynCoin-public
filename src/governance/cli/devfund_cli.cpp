#include "../../governance/devfund.h"
#include <iostream>

// CLI: Show Dev Fund Balance
void showDevFundBalanceCLI() {
    uint64_t balance = DevFund::getBalance();
    std::cout << "Developer Fund Balance: " << balance << " AlynCoin\n";
}

int main() {
    showDevFundBalanceCLI();
    return 0;
}
