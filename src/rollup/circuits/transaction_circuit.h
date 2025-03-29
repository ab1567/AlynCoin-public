#ifndef TRANSACTION_CIRCUIT_H
#define TRANSACTION_CIRCUIT_H

#include <string>
#include <vector>
#include <tuple>
#include <mutex>

class TransactionCircuit {
public:
    TransactionCircuit();

    void addTransactionData(const std::string& sender, const std::string& recipient, double amount, const std::string& txHash);
    void addTransactionBatch(const std::vector<std::tuple<std::string, std::string, double, std::string>>& batch);

    std::vector<std::string> getTrace() const;
    std::string getMerkleRoot() const;

private:
    std::vector<std::string> transactionTrace;
    std::string merkleRoot;
    std::mutex traceMutex;

    void computeMerkleRoot();
};

#endif // TRANSACTION_CIRCUIT_H
