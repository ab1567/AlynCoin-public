#include <filesystem>
#include <string>
#include <iostream>
#include "db/db_paths.h"

const std::string KEY_DIR = DBPaths::getKeyDir();

std::string getPrivateKeyPath(const std::string &username) {
  if (!std::filesystem::exists(KEY_DIR)) {
    std::error_code ec;
    std::filesystem::create_directories(KEY_DIR, ec);
    if (ec) {
      std::cerr << "⚠️ Failed to create key directory '" << KEY_DIR
                << "': " << ec.message() << "\n";
    }
  }
  return KEY_DIR + username + "_private.pem";
}

std::string getPublicKeyPath(const std::string &username) {
  if (!std::filesystem::exists(KEY_DIR)) {
    std::error_code ec;
    std::filesystem::create_directories(KEY_DIR, ec);
    if (ec) {
      std::cerr << "⚠️ Failed to create key directory '" << KEY_DIR
                << "': " << ec.message() << "\n";
    }
  }
  return KEY_DIR + username + "_public.pem";
}
