
#include "state_circuit.h"
#include "../rollup_utils.h"
#include <sstream>
#include <stdexcept>

StateCircuit::StateCircuit() {}

void StateCircuit::addAccountState(const std::string& address, double balance) {
    if (accountStates.find(address) != accountStates.end()) {
        throw std::runtime_error("Account already exists in the state circuit.");
    }
    accountStates[address] = balance;
}

void StateCircuit::updateAccountBalance(const std::string& address, double newBalance) {
    if (accountStates.find(address) == accountStates.end()) {
        throw std::runtime_error("Account does not exist in the state circuit.");
    }
    accountStates[address] = newBalance;
}

double StateCircuit::getAccountBalance(const std::string& address) const {
    auto it = accountStates.find(address);
    if (it == accountStates.end()) {
        throw std::runtime_error("Account does not exist in the state circuit.");
    }
    return it->second;
}

std::string StateCircuit::computeStateRootHash() const {
    std::vector<std::string> accountHashes;
    for (const auto& [address, balance] : accountStates) {
        accountHashes.push_back(hashAccountData(address, balance));
    }
    return RollupUtils::calculateMerkleRoot(accountHashes);
}

std::vector<std::string> StateCircuit::generateStateTrace() const {
    std::vector<std::string> stateTrace;
    for (const auto& [address, balance] : accountStates) {
        stateTrace.push_back(hashAccountData(address, balance));
    }
    return stateTrace;
}

const std::unordered_map<std::string, double>& StateCircuit::getAccountStates() const {
    return accountStates;
}

std::string StateCircuit::hashAccountData(const std::string& address, double balance) const {
    std::ostringstream ss;
    ss << address << balance;
    return RollupUtils::hybridHashWithDomain(ss.str(), "StateTrace");
}

