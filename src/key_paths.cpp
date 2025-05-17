#include <filesystem>
#include <string>
#include "db/db_paths.h"

const std::string KEY_DIR = DBPaths::getKeyDir();

std::string getPrivateKeyPath(const std::string &username) {
  if (!std::filesystem::exists(KEY_DIR)) {
    std::filesystem::create_directories(KEY_DIR);
  }
  return KEY_DIR + username + "_private.pem";
}

std::string getPublicKeyPath(const std::string &username) {
  if (!std::filesystem::exists(KEY_DIR)) {
    std::filesystem::create_directories(KEY_DIR);
  }
  return KEY_DIR + username + "_public.pem";
}
