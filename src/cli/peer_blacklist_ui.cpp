// peer_blacklist_ui.cpp
#include "peer_blacklist_cli.h"
#include "../network/peer_blacklist.h"
#include <iostream>

void showBlacklist(PeerBlacklist* blacklist) {
    auto entries = blacklist->getAllEntries();
    for (const auto& entry : entries) {
        std::cout << "Peer: " << entry.peer_id
                  << " | Strikes: " << entry.strikes
                  << " | Reason: " << entry.reason
                  << " | Timestamp: " << entry.timestamp
                  << std::endl;
    }
}

void clearBlacklist(PeerBlacklist* blacklist) {
    if (blacklist->clearBlacklist()) {
        std::cout << "Blacklist cleared." << std::endl;
    } else {
        std::cout << "Failed to clear blacklist." << std::endl;
    }
}

void removePeer(PeerBlacklist* blacklist, const std::string& peer_id) {
    if (blacklist->removePeer(peer_id)) {
        std::cout << "Removed peer: " << peer_id << std::endl;
    } else {
        std::cout << "Failed to remove peer: " << peer_id << std::endl;
    }
}

void addPeer(PeerBlacklist* blacklist, const std::string& peer_id, const std::string& reason) {
    if (blacklist->addPeer(peer_id, reason)) {
        std::cout << "Manually added peer to blacklist: " << peer_id << std::endl;
    } else {
        std::cout << "Failed to add peer to blacklist." << std::endl;
    }
}
