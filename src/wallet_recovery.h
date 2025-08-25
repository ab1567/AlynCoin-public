#pragma once
#include <string>
#include <vector>
#include <optional>
#include <utility>

struct GuardianInfo {
    std::string address;
    std::string fingerprint;
};

struct RecoveryIntent {
    std::string id;
    std::string newPassHash;
    int m = 0;
    int n = 0;
    long lockDeadline = 0; // unix timestamp
    std::string initiator;
    long timestamp = 0;
    std::vector<std::pair<std::string, std::string>> approvals; // guardian -> signature
    bool finalized = false;
};

class WalletRecovery {
public:
    static bool addGuardian(const std::string& wallet, const GuardianInfo& g);
    static bool removeGuardian(const std::string& wallet, const std::string& address);
    static std::vector<GuardianInfo> listGuardians(const std::string& wallet);

    static RecoveryIntent initRecovery(const std::string& wallet,
                                       const std::string& newPass,
                                       int m, int n,
                                       int lockMinutes,
                                       const std::string& initiator);
    static bool approveRecovery(const std::string& wallet,
                                const std::string& id,
                                const std::string& guardian,
                                const std::string& signature);
    static std::optional<RecoveryIntent> getRecovery(const std::string& wallet,
                                                     const std::string& id);
    static bool finalizeRecovery(const std::string& wallet,
                                 const std::string& id);

private:
    static std::string guardianPath(const std::string& wallet);
    static std::string recoveryPath(const std::string& wallet);
};
