#include "transport/peer_globals.h"

std::unordered_map<std::string, std::shared_ptr<Transport>> peerTransports;
std::timed_mutex peersMutex;
