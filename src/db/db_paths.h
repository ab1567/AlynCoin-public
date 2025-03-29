#pragma once
#include <cstdlib>
#include <string>

namespace DBPaths {
    inline std::string getBlockchainDB() {
        const char* env = std::getenv("ALYNCOIN_BLOCKCHAIN_DB");
        return env ? std::string(env) : "/root/.alyncoin/blockchain_db";
    }

    inline std::string getTransactionDB() {
        const char* env = std::getenv("ALYNCOIN_TX_DB");
        return env ? std::string(env) : "/root/.alyncoin/transactions_db";
    }

    inline std::string getGovernanceDB() {
        const char* env = std::getenv("ALYNCOIN_GOV_DB");
        return env ? std::string(env) : "/root/.alyncoin/governance_db";
    }

    inline std::string getBlacklistDB() {
        const char* env = std::getenv("ALYNCOIN_BLACKLIST_DB");
        return env ? std::string(env) : "/root/.alyncoin/blacklist";
    }
}
