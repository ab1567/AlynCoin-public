// peer_blacklist_cli.cpp
#include "peer_blacklist_cli.h"
#include "../network/peer_blacklist.h"

int main() {
    PeerBlacklist blacklist("peers.txt", 3);
    // test logic or REPL here if needed
    return 0;
}
