#pragma once
#include <cstdlib>
#include <stdexcept>
#include <string>

namespace DBPaths {

inline std::string getHomePath() {
#ifdef _WIN32
  const char *home = std::getenv("ALYNCOIN_HOME");
  if (!home)
    home = std::getenv("USERPROFILE");
  if (!home)
    throw std::runtime_error("USERPROFILE not set; set ALYNCOIN_HOME");
#else
  const char *home = std::getenv("ALYNCOIN_HOME");
  if (!home)
    home = std::getenv("HOME");
  if (!home)
    home = "/root";
#endif
  return std::string(home);
}

inline std::string getBlockchainDB() {
  const char *env = std::getenv("ALYNCOIN_BLOCKCHAIN_DB");
  return env ? std::string(env) : getHomePath() + "/.alyncoin/blockchain_db";
}

inline std::string getTransactionDB() {
  const char *env = std::getenv("ALYNCOIN_TX_DB");
  return env ? std::string(env) : getHomePath() + "/.alyncoin/transactions_db";
}

inline std::string getGovernanceDB() {
  const char *env = std::getenv("ALYNCOIN_GOV_DB");
  return env ? std::string(env) : getHomePath() + "/.alyncoin/governance_db";
}

inline std::string getBlacklistDB() {
  const char *env = std::getenv("ALYNCOIN_BLACKLIST_DB");
  return env ? std::string(env) : getHomePath() + "/.alyncoin/blacklist";
}

inline std::string getKeyDir() {
  const char *env = std::getenv("ALYNCOIN_KEY_DIR");
  return env ? std::string(env) : getHomePath() + "/.alyncoin/keys/";
}

inline std::string getKeyPath(const std::string &address) {
  return getKeyDir() + address + "_combined.key";
}

inline std::string getIdentityDB() {
  const char *env = std::getenv("ALYNCOIN_IDENTITY_DB");
  return env ? std::string(env) : getHomePath() + "/.alyncoin/identity_db";
}

inline std::string getGenesisFile() {
  const char *env = std::getenv("ALYNCOIN_GENESIS_FILE");
  return env ? std::string(env)
             : getHomePath() + "/.alyncoin/genesis_block.bin";
}
} // namespace DBPaths
