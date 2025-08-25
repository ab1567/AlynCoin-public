#include "wallet_recovery.h"
#include "crypto_utils.h"
#include "db/db_paths.h"
#include <json/json.h>
#include <fstream>
#include <filesystem>
#include <ctime>

namespace fs = std::filesystem;

std::string WalletRecovery::guardianPath(const std::string& wallet) {
    return DBPaths::getHomePath() + "/.alyncoin/" + wallet + "_guardians.json";
}

std::string WalletRecovery::recoveryPath(const std::string& wallet) {
    return DBPaths::getHomePath() + "/.alyncoin/" + wallet + "_recoveries.json";
}

static Json::Value loadJson(const std::string& path) {
    std::ifstream in(path);
    if (!in.good()) return Json::Value(Json::objectValue);
    Json::Value root; in >> root; return root;
}

static void saveJson(const std::string& path, const Json::Value& root) {
    fs::create_directories(fs::path(path).parent_path());
    std::ofstream out(path);
    out << root.toStyledString();
}

bool WalletRecovery::addGuardian(const std::string& wallet, const GuardianInfo& g) {
    Json::Value root = loadJson(guardianPath(wallet));
    Json::Value& arr = root["guardians"];
    for (const auto& item : arr) {
        if (item["address"].asString() == g.address) return true; // idempotent
    }
    Json::Value obj(Json::objectValue);
    obj["address"] = g.address;
    obj["fingerprint"] = g.fingerprint;
    arr.append(obj);
    saveJson(guardianPath(wallet), root);
    return true;
}

bool WalletRecovery::removeGuardian(const std::string& wallet, const std::string& address) {
    Json::Value root = loadJson(guardianPath(wallet));
    Json::Value& arr = root["guardians"];
    Json::Value newArr(Json::arrayValue);
    for (const auto& item : arr) {
        if (item["address"].asString() != address) newArr.append(item);
    }
    arr = newArr;
    saveJson(guardianPath(wallet), root);
    return true;
}

std::vector<GuardianInfo> WalletRecovery::listGuardians(const std::string& wallet) {
    Json::Value root = loadJson(guardianPath(wallet));
    std::vector<GuardianInfo> out;
    for (const auto& item : root["guardians"]) {
        GuardianInfo g; g.address = item["address"].asString(); g.fingerprint = item["fingerprint"].asString();
        out.push_back(g);
    }
    return out;
}

RecoveryIntent WalletRecovery::initRecovery(const std::string& wallet,
                                            const std::string& newPass,
                                            int m, int n,
                                            int lockMinutes,
                                            const std::string& initiator) {
    Json::Value root = loadJson(recoveryPath(wallet));
    RecoveryIntent ri;
    ri.id = Crypto::generateRandomHex(8);
    ri.newPassHash = Crypto::sha256(newPass);
    ri.m = m; ri.n = n;
    ri.timestamp = std::time(nullptr);
    ri.lockDeadline = ri.timestamp + lockMinutes * 60;
    ri.initiator = initiator;
    Json::Value obj(Json::objectValue);
    obj["id"] = ri.id;
    obj["new_pass"] = ri.newPassHash;
    obj["m"] = m;
    obj["n"] = n;
    obj["timestamp"] = (Json::Int64)ri.timestamp;
    obj["lock_deadline"] = (Json::Int64)ri.lockDeadline;
    obj["initiator"] = initiator;
    obj["approvals"] = Json::arrayValue;
    obj["finalized"] = false;
    Json::Value& arr = root["recoveries"];
    if (!arr.isObject()) arr = Json::Value(Json::objectValue);
    arr[ri.id] = obj;
    saveJson(recoveryPath(wallet), root);
    return ri;
}

static Json::Value* findRecovery(Json::Value& root, const std::string& id) {
    Json::Value& recs = root["recoveries"];
    if (!recs.isObject()) return nullptr;
    Json::Value::Members mem = recs.getMemberNames();
    for (const auto& k : mem) {
        if (k == id) return &recs[k];
    }
    return nullptr;
}

std::optional<RecoveryIntent> WalletRecovery::getRecovery(const std::string& wallet,
                                                          const std::string& id) {
    Json::Value root = loadJson(recoveryPath(wallet));
    Json::Value* obj = findRecovery(root, id);
    if (!obj) return std::nullopt;
    RecoveryIntent ri;
    ri.id = id;
    ri.newPassHash = (*obj)["new_pass"].asString();
    ri.m = (*obj)["m"].asInt();
    ri.n = (*obj)["n"].asInt();
    ri.timestamp = (*obj)["timestamp"].asInt64();
    ri.lockDeadline = (*obj)["lock_deadline"].asInt64();
    ri.initiator = (*obj)["initiator"].asString();
    ri.finalized = (*obj)["finalized"].asBool();
    for (const auto& appr : (*obj)["approvals"]) {
        ri.approvals.push_back({appr["guardian"].asString(), appr["sig"].asString()});
    }
    return ri;
}

bool WalletRecovery::approveRecovery(const std::string& wallet,
                                     const std::string& id,
                                     const std::string& guardian,
                                     const std::string& signature) {
    Json::Value root = loadJson(recoveryPath(wallet));
    Json::Value* obj = findRecovery(root, id);
    if (!obj) return false;
    Json::Value& appr = (*obj)["approvals"];
    for (const auto& a : appr) {
        if (a["guardian"].asString() == guardian) return false; // duplicate
    }
    Json::Value entry(Json::objectValue);
    entry["guardian"] = guardian;
    entry["sig"] = signature;
    appr.append(entry);
    saveJson(recoveryPath(wallet), root);
    return true;
}

bool WalletRecovery::finalizeRecovery(const std::string& wallet,
                                      const std::string& id) {
    Json::Value root = loadJson(recoveryPath(wallet));
    Json::Value* obj = findRecovery(root, id);
    if (!obj) return false;
    if ((*obj)["finalized"].asBool()) return false;
    int m = (*obj)["m"].asInt();
    Json::Value& appr = (*obj)["approvals"];
    if ((int)appr.size() < m) return false;
    long deadline = (*obj)["lock_deadline"].asInt64();
    if (std::time(nullptr) < deadline) return false;
    (*obj)["finalized"] = true;
    std::string passPath = DBPaths::getKeyDir() + wallet + "_pass.txt";
    std::ofstream(passPath) << (*obj)["new_pass"].asString();
    saveJson(recoveryPath(wallet), root);
    return true;
}

