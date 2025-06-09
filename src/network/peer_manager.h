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
    std::map<std::string, int> peerHeights;
    std::map<std::string, std::string> peerTipHashes;
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

    bool fetchBlockAtHeight(int height, Block& outBlock);

    void setPeerHeight(const std::string& peer, int height);
    int getPeerHeight(const std::string& peer) const;
    std::string getPeerTipHash(const std::string& peer) const;
    void setPeerTipHash(const std::string& peer, const std::string& tipHash);
    void recordTipHash(const std::string& peer, const std::string& tipHash);
};

#endif // PEER_MANAGER_H
