#pragma once
#include <string>

struct AppConfig {
    bool enable_tls = false;
    bool enable_whisper = false;
    std::string data_dir = "./data";
};

AppConfig& getAppConfig();
