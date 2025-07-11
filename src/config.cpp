#include "config.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>

static void loadConfig(AppConfig &cfg) {
    std::ifstream in("config.toml");
    if (!in)
        return;
    auto trim = [](std::string &s) {
        s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char c){return !std::isspace(c);}));
        s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char c){return !std::isspace(c);}).base(), s.end());
    };
    std::string line;
    while (std::getline(in, line)) {
        auto posHash = line.find('#');
        if (posHash != std::string::npos)
            line = line.substr(0, posHash);
        trim(line);
        if (line.empty())
            continue;
        auto eq = line.find('=');
        if (eq == std::string::npos)
            continue;
        std::string key = line.substr(0, eq);
        std::string val = line.substr(eq + 1);
        trim(key);
        trim(val);
        if (key == "enable_tls")
            cfg.enable_tls = (val == "true");
        else if (key == "enable_whisper")
            cfg.enable_whisper = (val == "true");
        else if (key == "data_dir") {
            if (!val.empty() && val.front() == '"' && val.back() == '"')
                val = val.substr(1, val.size()-2);
            cfg.data_dir = val;
        } else if (key == "proxy_host") {
            if (!val.empty() && val.front() == '"' && val.back() == '"')
                val = val.substr(1, val.size()-2);
            cfg.proxy_host = val;
        } else if (key == "proxy_port")
            cfg.proxy_port = std::stoi(val);
        else if (key == "max_peers")
            cfg.max_peers = std::stoul(val);
        else if (key == "ban_threshold")
            cfg.ban_threshold = std::stoi(val);
        else if (key == "frame_limit_min")
            cfg.frame_limit_min = std::stoull(val);
        else if (key == "max_snapshot_chunk_size")
            cfg.max_snapshot_chunk_size = std::stoul(val);
    }
}

AppConfig& getAppConfig() {
    static AppConfig cfg;
    static bool loaded = false;
    if (!loaded) {
        loadConfig(cfg);
        loaded = true;
    }
    return cfg;
}
