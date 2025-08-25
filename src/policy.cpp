#include "policy.h"
#include "db/db_paths.h"
#include <fstream>
#include <ctime>
#include <set>
#include <cstdio>

Json::Value Policy::toJson() const {
    Json::Value j;
    j["multisig"]["m"] = m;
    j["multisig"]["n"] = n;
    j["daily_limit"] = daily_limit;
    for (const auto& a : allowlist) j["allowlist"].append(a);
    j["lock_large"]["threshold"] = lock_threshold;
    j["lock_large"]["minutes"] = lock_minutes;
    return j;
}

Policy Policy::fromJson(const Json::Value &j) {
    Policy p;
    if (j.isObject()) {
        const auto& ms = j["multisig"];
        if (ms.isObject()) {
            p.m = ms.get("m", 1).asInt();
            p.n = ms.get("n", 1).asInt();
        }
        p.daily_limit = j.get("daily_limit", 0.0).asDouble();
        const auto& al = j["allowlist"];
        if (al.isArray()) {
            for (const auto& a : al) p.allowlist.push_back(a.asString());
        }
        const auto& lock = j["lock_large"];
        if (lock.isObject()) {
            p.lock_threshold = lock.get("threshold", 0.0).asDouble();
            p.lock_minutes = lock.get("minutes", 0).asInt();
        }
    }
    return p;
}

static Json::Value readJson(const std::string& path) {
    std::ifstream in(path);
    if (!in.good()) return Json::Value();
    Json::Value j; in >> j; return j;
}

static void writeJson(const std::string& path, const Json::Value& j) {
    std::ofstream out(path);
    out << Json::writeString(Json::StreamWriterBuilder(), j);
}

static std::string spendPath(const std::string& addr);
static std::string holdPath(const std::string& addr);

std::string PolicyManager::policyPath(const std::string& addr) {
    return DBPaths::getHomePath() + "/.alyncoin/" + addr + "_policy.json";
}

Policy PolicyManager::load(const std::string& addr) {
    Json::Value j = readJson(policyPath(addr));
    return Policy::fromJson(j);
}

bool PolicyManager::save(const std::string& addr, const Policy& p) {
    writeJson(policyPath(addr), p.toJson());
    return true;
}

bool PolicyManager::clear(const std::string& addr) {
    std::remove(policyPath(addr).c_str());
    std::remove(spendPath(addr).c_str());
    std::remove(holdPath(addr).c_str());
    return true;
}

bool PolicyManager::exportPolicy(const std::string& addr, const std::string& path) {
    Json::Value j = load(addr).toJson();
    writeJson(path, j);
    return true;
}

bool PolicyManager::importPolicy(const std::string& addr, const std::string& path) {
    Json::Value j = readJson(path);
    Policy p = Policy::fromJson(j);
    return save(addr, p);
}

static std::string spendPath(const std::string& addr) {
    return DBPaths::getHomePath() + "/.alyncoin/" + addr + "_spend.json";
}
static std::string holdPath(const std::string& addr) {
    return DBPaths::getHomePath() + "/.alyncoin/" + addr + "_holds.json";
}

static double get24hSpent(const std::string& addr, double now, Json::Value& log) {
    log = readJson(spendPath(addr));
    if (!log.isArray()) log = Json::Value(Json::arrayValue);
    Json::Value newLog(Json::arrayValue);
    double sum = 0;
    for (const auto& e : log) {
        double t = e["t"].asDouble();
        double a = e["a"].asDouble();
        if (now - t <= 24*60*60) {
            newLog.append(e);
            sum += a;
        }
    }
    log = newLog;
    return sum;
}

static void saveSpendLog(const std::string& addr, const Json::Value& log) {
    writeJson(spendPath(addr), log);
}

static Json::Value readHolds(const std::string& addr) {
    Json::Value j = readJson(holdPath(addr));
    if (!j.isArray()) j = Json::Value(Json::arrayValue);
    return j;
}

static void saveHolds(const std::string& addr, const Json::Value& h) {
    writeJson(holdPath(addr), h);
}

bool PolicyManager::checkSend(const std::string& from, const std::string& to,
                              double amount,
                              const std::vector<std::string>& cosigners,
                              std::string& err) {
    Policy p = load(from);
    // Allowlist
    if (!p.allowlist.empty()) {
        bool ok = false;
        for (const auto& a : p.allowlist) if (a == to) { ok = true; break; }
        if (!ok) { err = "Recipient not in allowlist"; return false; }
    }
    double now = std::time(nullptr);
    // Daily limit
    if (p.daily_limit > 0) {
        Json::Value log; double spent = get24hSpent(from, now, log);
        if (amount > p.daily_limit - spent) {
            err = "Daily limit exceeded"; return false; }
    }
    // Lock large
    if (p.lock_threshold > 0 && amount >= p.lock_threshold) {
        Json::Value holds = readHolds(from);
        bool found = false; int index = -1; double release = 0;
        for (Json::ArrayIndex i=0;i<holds.size();++i) {
            auto &h = holds[i];
            if (h["to"].asString()==to && h["amt"].asDouble()==amount) {
                found = true; index = i; release = h["release"].asDouble(); break; }
        }
        if (!found) {
            Json::Value h; h["to"]=to; h["amt"]=amount; h["release"] = now + p.lock_minutes*60;
            holds.append(h); saveHolds(from, holds);
            err = "Amount requires time-lock; hold created"; return false;
        } else if (now < release) {
            err = "Transfer on hold until time-lock expires"; return false;
        } else {
            // release
            Json::Value newH(Json::arrayValue);
            for (Json::ArrayIndex i=0;i<holds.size();++i) if ((int)i!=index) newH.append(holds[i]);
            saveHolds(from, newH);
        }
    }
    // Multisig
    if (p.m > 1) {
        std::set<std::string> uniq(cosigners.begin(), cosigners.end());
        if ((int)uniq.size() < p.m - 1) {
            err = "Not enough co-signers"; return false; }
    }
    return true;
}

void PolicyManager::recordSpend(const std::string& addr, double amount) {
    double now = std::time(nullptr);
    Json::Value log; double spent = get24hSpent(addr, now, log);
    Json::Value entry; entry["t"] = now; entry["a"] = amount; log.append(entry);
    saveSpendLog(addr, log);
}
