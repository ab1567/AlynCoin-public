#pragma once
#include <cstdlib>
#include <filesystem>
#include <mutex>
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

inline std::string getBaseDir() {
  return getHomePath() + "/.alyncoin";
}

inline std::string getBlockchainDB() {
  const char *env = std::getenv("ALYNCOIN_BLOCKCHAIN_DB");
  return env ? std::string(env) : getBaseDir() + "/blockchain_db";
}

inline std::string getTransactionDB() {
  const char *env = std::getenv("ALYNCOIN_TX_DB");
  return env ? std::string(env) : getBaseDir() + "/transactions_db";
}

inline std::string getGovernanceDB() {
  const char *env = std::getenv("ALYNCOIN_GOV_DB");
  return env ? std::string(env) : getBaseDir() + "/governance_db";
}

inline std::string getBlacklistDB() {
  const char *env = std::getenv("ALYNCOIN_BLACKLIST_DB");
  return env ? std::string(env) : getBaseDir() + "/blacklist";
}

inline std::string ensureTrailingSeparator(const std::string &path) {
  if (path.empty()) {
    return path;
  }

  const char last = path.back();
  if (last == '/' || last == '\\') {
    return path;
  }

#ifdef _WIN32
  return path + "\\";
#else
  return path + "/";
#endif
}

inline std::string getKeyDir() {
  namespace fs = std::filesystem;

  const char *env = std::getenv("ALYNCOIN_KEY_DIR");
  fs::path keyDir = env ? fs::path(env) : fs::path(getBaseDir()) / "keys";

  keyDir = keyDir.lexically_normal();

  return ensureTrailingSeparator(keyDir.string());
}

inline std::string getKeyPath(const std::string &address) {
  return getKeyDir() + address + "_combined.key";
}

inline std::string getIdentityDB() {
  const char *env = std::getenv("ALYNCOIN_IDENTITY_DB");
  return env ? std::string(env) : getBaseDir() + "/identity_db";
}

inline std::string getGenesisFile() {
  const char *env = std::getenv("ALYNCOIN_GENESIS_FILE");
  return env ? std::string(env)
             : getBaseDir() + "/genesis_block.bin";
}

inline std::string getDataDir() {
  const char *env = std::getenv("ALYNCOIN_DATA_DIR");
  return env ? std::string(env) : getBaseDir() + "/data";
}

inline std::once_flag &ensureFlag() {
  static std::once_flag flag;
  return flag;
}

inline void ensureDirs() {
  std::call_once(ensureFlag(), []() {
    namespace fs = std::filesystem;

    const auto ensureDir = [](const std::string &path) {
      if (path.empty()) {
        return;
      }
      std::error_code ec;
      fs::create_directories(path, ec);
      if (ec) {
        throw std::runtime_error("Failed to create directory '" + path +
                                 "': " + ec.message());
      }
    };

    ensureDir(getBaseDir());
    ensureDir(getDataDir());
    ensureDir(getBlockchainDB());
    ensureDir(getTransactionDB());
    ensureDir(getGovernanceDB());
    ensureDir(getBlacklistDB());
    ensureDir(getKeyDir());
    ensureDir(getIdentityDB());
  });
}
} // namespace DBPaths
