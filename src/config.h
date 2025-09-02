#pragma once
#include <string>

struct AppConfig {
    bool enable_tls = false;
    bool enable_whisper = false;
    std::string data_dir = "./data";
  std::string proxy_host;
  int proxy_port = 0;
  int ban_minutes = 5;
  // Consensus: address binding rule
  bool rule_addr_binding = false;         // off by default
  int  addr_binding_activation_height = 0; // height X when rule becomes mandatory
};

AppConfig& getAppConfig();
void loadConfigFile(const std::string &path);
