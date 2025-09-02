#include "config.h"
#include <fstream>

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
    while (std::getline(in, line)) {
        if (line.rfind("ban_minutes=", 0) == 0) {
            cfg.ban_minutes = std::stoi(line.substr(12));
        } else if (line.rfind("rule_addr_binding=", 0) == 0) {
            std::string v = line.substr(std::string("rule_addr_binding=").size());
            // accept 1/0/true/false
            for (auto &c : v) c = static_cast<char>(::tolower(c));
            cfg.rule_addr_binding = (v == "1" || v == "true" || v == "yes");
        } else if (line.rfind("addr_binding_activation_height=", 0) == 0) {
            std::string v = line.substr(std::string("addr_binding_activation_height=").size());
            try { cfg.addr_binding_activation_height = std::stoi(v); } catch (...) {}
        }
    }
}
