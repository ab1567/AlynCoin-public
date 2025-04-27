#include "transaction_validator.h"
#include <iostream>

TransactionValidator::TransactionValidator(PeerBlacklist* bl) : blacklist(bl) {}

bool TransactionValidator::validateTransaction(const std::string& tx_data, const std::string& peer_id) {
    // Dummy validation (replace with real signature & double-spend logic)
    bool is_valid = true; // Placeholder

    // For demonstration: simulate failure if tx_data contains "invalid"
    if (tx_data.find("invalid") != std::string::npos) {
        is_valid = false;
    }

    if (!is_valid) {
        std::cout << "Invalid transaction detected from peer: " << peer_id << std::endl;
        blacklist->incrementStrike(peer_id, "Invalid transaction");
        return false;
    }

    std::cout << "Valid transaction from peer: " << peer_id << std::endl;
    return true;
}
