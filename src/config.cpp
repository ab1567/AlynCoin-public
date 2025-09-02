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
        }
    }
}
