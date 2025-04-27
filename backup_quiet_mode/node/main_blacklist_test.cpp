#include "network/peer_blacklist.h"
#include "network/peer_manager.h"
#include "validation/transaction_validator.h"

int main() {
    PeerBlacklist blacklist("./data/peer_blacklist.db");

    PeerManager peerManager(&blacklist);
    TransactionValidator txValidator(&blacklist);

    // Example usage:
    peerManager.connectToPeer("peer_pubkey_1");
    txValidator.validateTransaction("invalid_tx_data", "peer_pubkey_1"); // triggers strike
}
