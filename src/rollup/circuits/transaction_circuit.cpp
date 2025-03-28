#include "transaction_circuit.h"
#include "../rollup_utils.h"
#include <sstream>
#include <thread>

TransactionCircuit::TransactionCircuit() {}

void TransactionCircuit::addTransactionData(const std::string& sender, const std::string& recipient, double amount, const std::string& txHash) {
    std::ostringstream ss;
    ss << sender << recipient << amount << txHash;
    transactionTrace.push_back(RollupUtils::hybridHashWithDomain(ss.str(), "TxTrace"));
    computeMerkleRoot();
}

void TransactionCircuit::addTransactionBatch(const std::vector<std::tuple<std::string, std::string, double, std::string>>& batch) {
    std::vector<std::thread> threads;

    for (const auto& tx : batch) {
        threads.emplace_back([&]() {
            std::ostringstream ss;
            ss << std::get<0>(tx) << std::get<1>(tx) << std::get<2>(tx) << std::get<3>(tx);
            transactionTrace.push_back(RollupUtils::hybridHashWithDomain(ss.str(), "TxTrace"));
        });
    }

    for (auto& t : threads) t.join();

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
