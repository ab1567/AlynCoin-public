#pragma once
#include <unordered_map>
#include <memory>
#include <mutex>
#include "transport/transport.h"

// Canonical global peer table and mutex for the entire app:
extern std::unordered_map<std::string, std::shared_ptr<Transport>> peerTransports;
extern std::timed_mutex peersMutex;

