#ifndef PEER_BLACKLIST_CLI_H
#define PEER_BLACKLIST_CLI_H

#include "../network/peer_blacklist.h"

// Show all blacklisted peers
void showBlacklist(PeerBlacklist* blacklist);

// Clear all blacklist entries
void clearBlacklist(PeerBlacklist* blacklist);

// Remove specific peer manually
void removePeer(PeerBlacklist* blacklist, const std::string& peer_id);

// Add peer manually (optional)
void addPeer(PeerBlacklist* blacklist, const std::string& peer_id, const std::string& reason);

#endif // PEER_BLACKLIST_CLI_H
