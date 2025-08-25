#ifndef POLICY_H
#define POLICY_H

#include <string>
#include <vector>
#include <json/json.h>

struct Policy {
    int m = 1;
    int n = 1;
    double daily_limit = 0.0; // 0 => disabled
    std::vector<std::string> allowlist;
    double lock_threshold = 0.0; // 0 => disabled
    int lock_minutes = 0;

    Json::Value toJson() const;
    static Policy fromJson(const Json::Value &j);
};

class PolicyManager {
public:
    static Policy load(const std::string& addr);
    static bool save(const std::string& addr, const Policy& p);
    static bool clear(const std::string& addr);
    static bool exportPolicy(const std::string& addr, const std::string& path);
    static bool importPolicy(const std::string& addr, const std::string& path);

    static bool checkSend(const std::string& from, const std::string& to,
                          double amount,
                          const std::vector<std::string>& cosigners,
                          std::string& err);
    static void recordSpend(const std::string& addr, double amount);

private:
    static std::string policyPath(const std::string& addr);
};

#endif // POLICY_H
