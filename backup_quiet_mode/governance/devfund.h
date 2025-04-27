#ifndef DEVFUND_H
#define DEVFUND_H

#include <string>
#include <cstdint>

namespace DevFund {

// Add funds (e.g., % from block reward)
bool addFunds(uint64_t amount);

// Spend funds (only after DAO approval)
bool spendFunds(uint64_t amount, const std::string& recipientAddress);

// Get current balance
uint64_t getBalance();

// Initialize (load balance from RocksDB)
void initialize();

}

#endif // DEVFUND_H
