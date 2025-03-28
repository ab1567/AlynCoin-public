#include "devfund.h"
#include "../db/rocksdb_wrapper.h"
#include <mutex>

namespace DevFund {

static uint64_t currentBalance = 0;
static std::mutex fundMutex;
const std::string FUND_KEY = "devfund:balance";

// Load balance at startup
void initialize() {
    RocksDBWrapper db("/root/AlynCoin/data/governance_db");
    std::string value;
    if (db.get(FUND_KEY, value)) {
        currentBalance = std::stoull(value);
    } else {
        currentBalance = 0;
    }
}

// Add funds (from block reward, etc.)
bool addFunds(uint64_t amount) {
    std::lock_guard<std::mutex> lock(fundMutex);
    currentBalance += amount;
    RocksDBWrapper db("/root/AlynCoin/data/governance_db");
    return db.put(FUND_KEY, std::to_string(currentBalance));
}

// Spend funds (DAO approved)
bool spendFunds(uint64_t amount, const std::string& recipientAddress) {
    std::lock_guard<std::mutex> lock(fundMutex);
    if (amount > currentBalance) {
        return false; // Insufficient balance
    }
    currentBalance -= amount;
    RocksDBWrapper db("/root/AlynCoin/data/governance_db");
    // Store updated balance
    db.put(FUND_KEY, std::to_string(currentBalance));

    // Optionally: log recipient
    std::string logKey = "devfund:spent:" + recipientAddress;
    db.put(logKey, std::to_string(amount));

    return true;
}

// Get balance
uint64_t getBalance() {
    std::lock_guard<std::mutex> lock(fundMutex);
    return currentBalance;
}

} // namespace DevFund
