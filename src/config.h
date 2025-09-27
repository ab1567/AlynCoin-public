#pragma once
#include <string>

struct AppConfig {
    bool enable_tls = false;
    bool enable_whisper = false;
#ifdef _WIN32
    bool enable_upnp = true;
    bool enable_natpmp = true;
#else
    bool enable_upnp = false;
    bool enable_natpmp = false;
#endif
    std::string data_dir = "./data";
  std::string proxy_host;
  int proxy_port = 0;
  int ban_minutes = 5;
  // --- New RPC/PoR configuration ---
  std::string rpc_bind = "0.0.0.0:1567"; // host:port for RPC server
  std::string rpc_cors;                   // value for Access-Control-Allow-Origin
  int self_heal_interval = 0;             // seconds; 0 disables periodic self-heal
  std::string reserve_address;            // native reserve address for PoR
  double por_expected_walyn = 0.0;        // expected wrapped supply for PoR comparison
  std::string external_address;           // externally reachable <ip:port>
};

AppConfig& getAppConfig();
void loadConfigFile(const std::string &path);
void saveConfigValue(const std::string &path, const std::string &key,
                     const std::string &value);
