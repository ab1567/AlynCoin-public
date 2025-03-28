#include "layer2_rollups.h"
#include <iostream>

// Constructor for Rollup
Rollup::Rollup(std::string rollupId, int batchSize) : rollupId(rollupId), batchSize(batchSize) {
    std::cout << "Rollup created with ID: " << rollupId << " and batch size: " << batchSize << "\n";
}

// Method to add transactions to the rollup
bool Rollup::addTransaction(const std::string& transaction) {
    if (transactions.size() < batchSize) {
        transactions.push_back(transaction);
        std::cout << "Transaction added to rollup: " << transaction << "\n";
        return true;
    }
    std::cout << "Rollup batch full. Submit to Layer-1!\n";
    return false;
}

// Method to submit the rollup to Layer-1
bool Rollup::submitToLayer1() {
    std::cout << "Submitting rollup with " << transactions.size() << " transactions to Layer-1...\n";
    // Here, transactions are submitted to the Layer-1 chain
    return true;
}
