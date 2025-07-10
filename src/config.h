#pragma once
#include <string>
#include <thread>

struct AppConfig {
    bool enable_tls = false;
    bool enable_whisper = false;
    std::string data_dir = "./data";
    std::string proxy_host;
    int proxy_port = 0;
    unsigned verify_threads = std::thread::hardware_concurrency() * 2;
};

AppConfig& getAppConfig();
