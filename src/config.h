#pragma once
#include <string>

struct AppConfig {
    bool enable_tls = false;
    bool enable_whisper = false;
    std::string data_dir = "./data";
  std::string proxy_host;
  int proxy_port = 0;
  int ban_minutes = 5;
};

AppConfig& getAppConfig();
void loadConfigFile(const std::string &path);
