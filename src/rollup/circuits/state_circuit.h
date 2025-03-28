#ifndef STATE_CIRCUIT_H
#define STATE_CIRCUIT_H

#include <string>
#include <unordered_map>
#include <vector>

class StateCircuit {
public:
    StateCircuit();

    void addAccountState(const std::string& address, double balance);
    void updateAccountBalance(const std::string& address, double newBalance);
    double getAccountBalance(const std::string& address) const;

    std::string computeStateRootHash() const;
    std::vector<std::string> generateStateTrace() const;

    const std::unordered_map<std::string, double>& getAccountStates() const;

private:
    std::unordered_map<std::string, double> accountStates;
    std::string hashAccountData(const std::string& address, double balance) const;
};

#endif // STATE_CIRCUIT_H
