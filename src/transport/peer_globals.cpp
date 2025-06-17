#include "transport/peer_globals.h"

std::unordered_map<std::string, PeerEntry> peerTransports;
std::timed_mutex peersMutex;
