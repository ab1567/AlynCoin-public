#include "config.h"
#include <algorithm>
#include <cctype>
#include <fstream>
#include <vector>

AppConfig& getAppConfig() {
    static AppConfig cfg;
    return cfg;
}

void loadConfigFile(const std::string &path) {
    std::ifstream in(path);
    if (!in.is_open())
        return;
    std::string line;
    auto &cfg = getAppConfig();
    auto parseBool = [](std::string value) {
        value.erase(std::remove_if(value.begin(), value.end(), [](unsigned char ch) {
                         return std::isspace(ch) != 0;
                     }),
                     value.end());
        std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        return value == "1" || value == "true" || value == "yes" || value == "on";
    };

    auto trim = [](std::string value) {
        auto notSpace = [](int ch) { return std::isspace(ch) == 0; };
        value.erase(value.begin(), std::find_if(value.begin(), value.end(), notSpace));
        value.erase(std::find_if(value.rbegin(), value.rend(), notSpace).base(), value.end());
        return value;
    };

    bool seedsReset = false;

    while (std::getline(in, line)) {
        if (line.rfind("ban_minutes=", 0) == 0) {
            cfg.ban_minutes = std::stoi(line.substr(12));
        } else if (line.rfind("offline_mode=", 0) == 0) {
            cfg.offline_mode = parseBool(line.substr(13));
        } else if (line.rfind("allow_dns_bootstrap=", 0) == 0) {
            cfg.allow_dns_bootstrap = parseBool(line.substr(20));
        } else if (line.rfind("allow_peer_exchange=", 0) == 0) {
            cfg.allow_peer_exchange = parseBool(line.substr(20));
        } else if (line.rfind("allow_manual_peers=", 0) == 0) {
            cfg.allow_manual_peers = parseBool(line.substr(19));
        } else if (line.rfind("require_peer_for_mining=", 0) == 0) {
            cfg.require_peer_for_mining = parseBool(line.substr(24));
        } else if (line.rfind("rpc_bind=", 0) == 0) {
            cfg.rpc_bind = line.substr(10);
        } else if (line.rfind("rpc_cors=", 0) == 0) {
            cfg.rpc_cors = line.substr(9);
        } else if (line.rfind("self_heal_interval=", 0) == 0) {
            cfg.self_heal_interval = std::stoi(line.substr(18));
        } else if (line.rfind("reserve_address=", 0) == 0) {
            cfg.reserve_address = line.substr(16);
        } else if (line.rfind("por_expected_walyn=", 0) == 0) {
            cfg.por_expected_walyn = std::stod(line.substr(18));
        } else if (line.rfind("enable_upnp=", 0) == 0) {
            cfg.enable_upnp = parseBool(line.substr(12));
        } else if (line.rfind("enable_natpmp=", 0) == 0) {
            cfg.enable_natpmp = parseBool(line.substr(14));
        } else if (line.rfind("external_address=", 0) == 0) {
            cfg.external_address = line.substr(17);
        } else if (line.rfind("hide_peer_endpoints=", 0) == 0) {
            cfg.hide_peer_endpoints = parseBool(line.substr(20));
        } else if (line.rfind("seed=", 0) == 0) {
            std::string host = trim(line.substr(5));
            if (host.empty())
                continue;
            if (!seedsReset) {
                cfg.seed_hosts.clear();
                seedsReset = true;
            }
            auto exists = std::find_if(cfg.seed_hosts.begin(), cfg.seed_hosts.end(),
                                       [&](const std::string &existing) {
                                           return existing == host;
                                       });
            if (exists == cfg.seed_hosts.end())
                cfg.seed_hosts.push_back(std::move(host));
        }
    }

    if (seedsReset && cfg.seed_hosts.empty())
        cfg.seed_hosts.push_back("peers.alyncoin.com");
}

void saveConfigValue(const std::string &path, const std::string &key,
                     const std::string &value) {
    std::ifstream in(path);
    std::vector<std::string> lines;
    bool updated = false;
    std::string line;
    if (in.is_open()) {
        while (std::getline(in, line)) {
            if (line.rfind(key + '=', 0) == 0) {
                lines.push_back(key + '=' + value);
                updated = true;
            } else {
                lines.push_back(line);
            }
        }
        in.close();
    }
    if (!updated) {
        lines.push_back(key + '=' + value);
    }

    std::ofstream out(path, std::ios::trunc);
    if (!out.is_open())
        return;
    for (size_t i = 0; i < lines.size(); ++i) {
        out << lines[i];
        if (i + 1 != lines.size())
            out << '\n';
    }
}
