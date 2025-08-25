#pragma once
#include <string>
#include <vector>
#include <map>
#include "l2_account.h"

// Simple in-memory state manager using maps and Keccak hashing.
class L2StateManager {
public:
    // Deploys Wasm code and returns new account address.
    std::string deploy(const std::vector<uint8_t>& code);

    // Reads storage value for key (hex-encoded key).
    std::vector<uint8_t> readStorage(const std::string& addr,
                                     const std::vector<uint8_t>& key) const;

    // Writes storage value for key (hex-encoded).
    void writeStorage(const std::string& addr,
                      const std::vector<uint8_t>& key,
                      const std::vector<uint8_t>& value);

    // Returns account by address (throws if missing).
    L2Account& getAccount(const std::string& addr);

    // Compute current global state root hash.
    std::vector<uint8_t> stateRoot();

    // Access to stored Wasm code by codeHash.
    const std::vector<uint8_t>& getCode(const std::string& codeHash) const;

    std::map<std::string, std::vector<uint8_t>>
    getStorage(const std::string& addr) const;

    void setStorage(const std::string& addr,
                    const std::map<std::string, std::vector<uint8_t>>& m);

    L2Account& ensureAccount(const std::string& addr);

private:
    std::map<std::string, L2Account> accounts;
    std::map<std::string, std::map<std::string, std::vector<uint8_t>>> storage; // addr -> key -> value
    std::map<std::string, std::vector<uint8_t>> codeDb; // codeHash -> code bytes
};
