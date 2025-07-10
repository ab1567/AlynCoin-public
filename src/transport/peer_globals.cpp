#include "transport/peer_globals.h"

std::unordered_map<std::string, PeerEntry> peerTransports;
std::shared_mutex peersMutex;
