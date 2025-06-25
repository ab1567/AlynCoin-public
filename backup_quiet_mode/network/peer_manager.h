#ifndef PEER_MANAGER_H
#define PEER_MANAGER_H

#include <string>
#include <vector>
#include <map>
#include "peer_blacklist.h"
#include "block.h"

class Network; // Forward declaration

class PeerManager {
private:
    std::vector<std::string> connected_peers;
    PeerBlacklist* blacklist;
    Network* network;

public:
        PeerManager(PeerBlacklist* bl, Network* net = nullptr);

    bool connectToPeer(const std::string& peer_id);
    void disconnectPeer(const std::string& peer_id);

    std::vector<std::string> getConnectedPeers();
    int getPeerCount() const;

    uint64_t getMedianNetworkHeight();
    std::string getMajorityTipHash();

    // Additional helpers used by self-healing logic
    int getMaxPeerHeight() const { return 0; }
    std::string getConsensusTipHash(int) const { return getMajorityTipHash(); }

    bool fetchBlockAtHeight(int height, Block& outBlock);
};

#endif // PEER_MANAGER_H
