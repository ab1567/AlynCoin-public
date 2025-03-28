#include "peer_manager.h"
#include <iostream>

PeerManager::PeerManager(PeerBlacklist* bl) : blacklist(bl) {}

bool PeerManager::connectToPeer(const std::string& peer_id) {
    if (blacklist->isBlacklisted(peer_id)) {
        std::cout << "Rejected connection from blacklisted peer: " << peer_id << std::endl;
        return false;
    }

    connected_peers.push_back(peer_id);
    std::cout << "Connected to peer: " << peer_id << std::endl;
    return true;
}

void PeerManager::disconnectPeer(const std::string& peer_id) {
    connected_peers.erase(
        std::remove(connected_peers.begin(), connected_peers.end(), peer_id),
        connected_peers.end()
    );
    std::cout << "Disconnected peer: " << peer_id << std::endl;
}

std::vector<std::string> PeerManager::getConnectedPeers() {
    return connected_peers;
}
