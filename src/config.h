#pragma once
#include <string>

struct AppConfig {
    bool enable_tls = false;
    bool enable_whisper = false;
    std::string data_dir = "./data";
  std::string proxy_host;
  int proxy_port = 0;
  int ban_minutes = 5;
  // --- New RPC/PoR configuration ---
  std::string rpc_bind = "127.0.0.1:1567"; // host:port for RPC server
  std::string rpc_cors;                   // value for Access-Control-Allow-Origin
  int self_heal_interval = 0;             // seconds; 0 disables periodic self-heal
  std::string reserve_address;            // native reserve address for PoR
  double por_expected_walyn = 0.0;        // expected wrapped supply for PoR comparison
};

AppConfig& getAppConfig();
void loadConfigFile(const std::string &path);
