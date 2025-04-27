#ifndef STATE_CIRCUIT_H
#define STATE_CIRCUIT_H

#include <string>
#include <unordered_map>
#include <vector>

class StateCircuit {
public:
    StateCircuit();

    // ✅ Populate or modify state
    void addOrUpdateAccount(const std::string& address, double balance);

    // ⚠️ Optional strict update (used only when account must exist)
    void updateAccountBalance(const std::string& address, double newBalance);
    double getAccountBalance(const std::string& address) const;

    // ✅ Hash commitments
    std::string computeStateRootHash() const;
    std::vector<std::string> generateStateTrace() const;

    // ✅ Access full state map
    const std::unordered_map<std::string, double>& getAccountStates() const;

    // ✅ Load full state (for before/after comparison)
    void loadFullState(const std::unordered_map<std::string, double>& stateMap);

    // :
   void addAccountState(const std::string& address, double balance);


private:
    std::unordered_map<std::string, double> accountStates;
    std::string hashAccountData(const std::string& address, double balance) const;
};

#endif // STATE_CIRCUIT_H
