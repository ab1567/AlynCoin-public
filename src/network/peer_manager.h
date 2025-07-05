#ifndef PEER_MANAGER_H
#define PEER_MANAGER_H

#include <string>
#include <vector>
#include <map>
#include <cstdint>
#include "peer_blacklist.h"
#include "block.h"

class Network; // Forward declaration

class PeerManager {
private:
    std::vector<std::string> connected_peers;
    std::map<std::string, int> peerHeights;
    std::map<std::string, uint64_t> peerWorks;
    std::map<std::string, std::string> peerTipHashes;
    uint64_t localWork = 0;
    PeerBlacklist* blacklist;
    Network* network;

public:
    PeerManager(PeerBlacklist* bl, Network* net = nullptr);

    bool connectToPeer(const std::string& peer_id);
    bool registerPeer(const std::string& peer_id);
    void disconnectPeer(const std::string& peer_id);

    std::vector<std::string> getConnectedPeers();
    int getPeerCount() const;

    uint64_t getMedianNetworkHeight();
    std::string getMajorityTipHash() const;

    bool fetchBlockAtHeight(int height, Block& outBlock);

    void setPeerHeight(const std::string& peer, int height);
    int getPeerHeight(const std::string& peer) const;
    std::string getPeerTipHash(const std::string& peer) const;
    void setPeerTipHash(const std::string& peer, const std::string& tipHash);
    void recordTipHash(const std::string& peer, const std::string& tipHash);

    // New work tracking helpers
    void setLocalWork(uint64_t work);
    uint64_t getLocalWork() const;
    void setPeerWork(const std::string& peer, uint64_t work);
    uint64_t getPeerWork(const std::string& peer) const;
    uint64_t getMaxPeerWork() const;

    // --- New helpers for chain health ---------------------------------
    int getMaxPeerHeight() const;
    std::string getConsensusTipHash(int localHeight) const;
};

#endif // PEER_MANAGER_H
