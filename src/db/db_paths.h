#pragma once
#include <cstdlib>
#include <string>

namespace DBPaths {

    inline std::string getHomePath() {
#ifdef _WIN32
        // Prefer Windows user home variables; fall back to HOME if present.
        if (const char* up = std::getenv("USERPROFILE"); up && *up) {
            return std::string(up);
        }
        if (const char* home = std::getenv("HOME"); home && *home) {
            return std::string(home);
        }
        const char* drive = std::getenv("HOMEDRIVE");
        const char* path  = std::getenv("HOMEPATH");
        if (drive && path) {
            return std::string(drive) + std::string(path);
        }
        // Last resort on Windows: a public user directory
        return std::string("C:/Users/Public");
#else
        const char* home = std::getenv("HOME");
        return home ? std::string(home) : "/root";  // default fallback
#endif
    }

    inline std::string getBlockchainDB() {
        const char* env = std::getenv("ALYNCOIN_BLOCKCHAIN_DB");
        return env ? std::string(env) : getHomePath() + "/.alyncoin/blockchain_db";
    }

    inline std::string getTransactionDB() {
        const char* env = std::getenv("ALYNCOIN_TX_DB");
        return env ? std::string(env) : getHomePath() + "/.alyncoin/transactions_db";
    }

    inline std::string getGovernanceDB() {
        const char* env = std::getenv("ALYNCOIN_GOV_DB");
        return env ? std::string(env) : getHomePath() + "/.alyncoin/governance_db";
    }

    inline std::string getBlacklistDB() {
        const char* env = std::getenv("ALYNCOIN_BLACKLIST_DB");
        return env ? std::string(env) : getHomePath() + "/.alyncoin/blacklist";
    }

    inline std::string getKeyDir() {
        const char* env = std::getenv("ALYNCOIN_KEY_DIR");
        return env ? std::string(env) : getHomePath() + "/.alyncoin/keys/";
    }

    inline std::string getIdentityDB() {
        const char* env = std::getenv("ALYNCOIN_IDENTITY_DB");
        return env ? std::string(env) : getHomePath() + "/.alyncoin/identity_db";
    }

    inline std::string getGenesisFile() {
        const char* env = std::getenv("ALYNCOIN_GENESIS_FILE");
        return env ? std::string(env) : getHomePath() + "/.alyncoin/genesis_block.bin";
    }
}
