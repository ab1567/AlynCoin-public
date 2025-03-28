#ifndef PEER_MANAGER_H
#define PEER_MANAGER_H

#include <string>
#include <vector>
#include "peer_blacklist.h"

class PeerManager {
private:
    std::vector<std::string> connected_peers;
    PeerBlacklist* blacklist; // Blacklist pointer

public:
    PeerManager(PeerBlacklist* bl);

    bool connectToPeer(const std::string& peer_id);
    void disconnectPeer(const std::string& peer_id);
    std::vector<std::string> getConnectedPeers();
};

#endif // PEER_MANAGER_H
