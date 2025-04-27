#include "transaction_circuit.h"
#include "../rollup_utils.h"
#include <sstream>
#include <thread>

TransactionCircuit::TransactionCircuit() {}

void TransactionCircuit::addTransactionData(const std::string& sender, const std::string& recipient, double amount, const std::string& txHash) {
    std::ostringstream ss;
    ss << sender << recipient << amount << txHash;
    std::string hashed = RollupUtils::hybridHashWithDomain(ss.str(), "TxTrace");

    {
        std::lock_guard<std::mutex> lock(traceMutex);
        transactionTrace.push_back(hashed);
    }

    computeMerkleRoot();
}

void TransactionCircuit::addTransactionBatch(const std::vector<std::tuple<std::string, std::string, double, std::string>>& batch) {
    std::vector<std::string> localHashes(batch.size());

    std::vector<std::thread> threads;
    for (size_t i = 0; i < batch.size(); ++i) {
        threads.emplace_back([&, i]() {
            const auto& [sender, recipient, amount, txHash] = batch[i];
            std::ostringstream ss;
            ss << sender << recipient << amount << txHash;
            localHashes[i] = RollupUtils::hybridHashWithDomain(ss.str(), "TxTrace");
        });
    }

    for (auto& t : threads) t.join();

    {
        std::lock_guard<std::mutex> lock(traceMutex);
        transactionTrace.insert(transactionTrace.end(), localHashes.begin(), localHashes.end());
    }

    computeMerkleRoot();
}

std::vector<std::string> TransactionCircuit::getTrace() const {
    return transactionTrace;
}

void TransactionCircuit::computeMerkleRoot() {
    merkleRoot = RollupUtils::calculateMerkleRoot(transactionTrace);
}

std::string TransactionCircuit::getMerkleRoot() const {
    return merkleRoot;
}
