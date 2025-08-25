#include "l2_state.h"
#include "keccak.h"
#include "crypto_utils.h"
#include <stdexcept>

using Bytes = std::vector<uint8_t>;

static Bytes toBytes(uint64_t v) {
    Bytes out(8);
    for (int i = 7; i >= 0; --i) { out[i] = v & 0xFF; v >>= 8; }
    return out;
}

std::string L2StateManager::deploy(const Bytes& code) {
    auto hash = Keccak::keccak256_raw(code);
    std::string codeHash = Crypto::toHex(hash);
    std::string addr = codeHash.substr(0, 40); // 20 bytes hex
    L2Account acc;
    acc.address = addr;
    acc.codeHash = codeHash;
    acc.storageRoot = std::string(64, '0');
    accounts[addr] = acc;
    storage[addr] = {};
    codeDb[codeHash] = code;
    return addr;
}

Bytes L2StateManager::readStorage(const std::string& addr, const Bytes& key) const {
    auto ait = storage.find(addr);
    if (ait == storage.end()) return {};
    std::string keyHex = Crypto::toHex(key);
    auto it = ait->second.find(keyHex);
    if (it == ait->second.end()) return {};
    return it->second;
}

void L2StateManager::writeStorage(const std::string& addr, const Bytes& key, const Bytes& value) {
    storage[addr][Crypto::toHex(key)] = value;
}

L2Account& L2StateManager::getAccount(const std::string& addr) {
    auto it = accounts.find(addr);
    if (it == accounts.end()) throw std::runtime_error("account not found");
    return it->second;
}

const Bytes& L2StateManager::getCode(const std::string& codeHash) const {
    auto it = codeDb.find(codeHash);
    if (it == codeDb.end()) throw std::runtime_error("code not found");
    return it->second;
}

Bytes L2StateManager::stateRoot() {
    Bytes accConcat;
    for (auto& [addr, acc] : accounts) {
        // Compute storage root
        Bytes storageConcat;
        for (auto& [khex, val] : storage[addr]) {
            Bytes keyBytes = Crypto::fromHex(khex);
            storageConcat.insert(storageConcat.end(), keyBytes.begin(), keyBytes.end());
            storageConcat.insert(storageConcat.end(), val.begin(), val.end());
        }
        auto sroot = Keccak::keccak256_raw(storageConcat);
        acc.storageRoot = Crypto::toHex(sroot);
        // Account hash
        Bytes data = Crypto::fromHex(acc.address);
        auto ch = Crypto::fromHex(acc.codeHash);
        auto sr = Crypto::fromHex(acc.storageRoot);
        Bytes nonceBytes = toBytes(acc.nonce);
        Bytes balBytes = toBytes(acc.balance);
        data.insert(data.end(), ch.begin(), ch.end());
        data.insert(data.end(), sr.begin(), sr.end());
        data.insert(data.end(), nonceBytes.begin(), nonceBytes.end());
        data.insert(data.end(), balBytes.begin(), balBytes.end());
        auto ah = Keccak::keccak256_raw(data);
        accConcat.insert(accConcat.end(), ah.begin(), ah.end());
    }
    return Keccak::keccak256_raw(accConcat);
}

std::map<std::string, Bytes> L2StateManager::getStorage(const std::string& addr) const {
    auto it = storage.find(addr);
    if (it == storage.end()) return {};
    return it->second;
}

void L2StateManager::setStorage(const std::string& addr,
                                const std::map<std::string, Bytes>& m) {
    storage[addr] = m;
}

L2Account& L2StateManager::ensureAccount(const std::string& addr) {
    auto it = accounts.find(addr);
    if (it == accounts.end()) {
        L2Account a; a.address = addr; accounts[addr] = a; storage[addr] = {}; return accounts[addr];
    }
    return it->second;
}
