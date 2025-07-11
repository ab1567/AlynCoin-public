#pragma once
#include <string>
#include "constants.h"

struct AppConfig {
    bool enable_tls = false;
    bool enable_whisper = false;
    std::string data_dir = "./data";
    std::string proxy_host;
    int proxy_port = 0;
    std::size_t max_peers = DEFAULT_MAX_PEERS;
    int ban_threshold = 200;
    uint64_t frame_limit_min = 200;
    std::size_t max_snapshot_chunk_size = DEFAULT_MAX_SNAPSHOT_CHUNK_SIZE;
};

AppConfig& getAppConfig();
