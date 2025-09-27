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

    while (std::getline(in, line)) {
        if (line.rfind("ban_minutes=", 0) == 0) {
            cfg.ban_minutes = std::stoi(line.substr(12));
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
        }
    }
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
