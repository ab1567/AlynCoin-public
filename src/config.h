#pragma once
#include <string>
#include <vector>

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
    bool offline_mode = false;              // disable outbound networking
    bool allow_dns_bootstrap = true;        // seed peers via DNS/default list
    bool allow_peer_exchange = true;        // accept peers learned from gossip
    bool allow_manual_peers = false;        // ignore peers.txt/--connect overrides
    std::vector<std::string> seed_hosts{"peers.alyncoin.com"};
    bool no_self_dial = true;               // guard against dialing our own endpoint
    std::vector<std::string> static_peer_deny; // host[:port] entries to skip outbound dials
    bool require_peer_for_mining = true;    // enforce >=1 connected peer before mining
    // --- New RPC/PoR configuration ---
    std::string rpc_bind = "0.0.0.0:1567"; // host:port for RPC server
    std::string rpc_cors;                   // value for Access-Control-Allow-Origin
    int self_heal_interval = 0;             // seconds; 0 disables periodic self-heal
    std::string reserve_address;            // native reserve address for PoR
    double por_expected_walyn = 0.0;        // expected wrapped supply for PoR comparison
    std::string external_address;           // externally reachable <ip:port>
    bool hide_peer_endpoints = true;        // suppress peer IP/port details in UIs
    std::string peer_log_mode = "tag";      // off|tag|masked|full (controls log detail)

    // --- Sync/validation tuning ---
    bool quiet_sync_logs = false;           // suppress per-block validation logs
    bool fast_sync = false;                 // allow sampled validation during snapshot apply
    double fast_sync_sample_rate = 0.10;    // fraction of blocks to fully verify in fast sync
    int fast_sync_trailing_full = 12;       // always fully verify this many trailing blocks
};

AppConfig& getAppConfig();
void loadConfigFile(const std::string &path);
void saveConfigValue(const std::string &path, const std::string &key,
                     const std::string &value);
