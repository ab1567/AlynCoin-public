#ifndef SYNC_RECOVERY_H
#define SYNC_RECOVERY_H

#include <string>

class Blockchain;
class PeerManager;
class Block;

class SyncRecovery {
public:
    SyncRecovery(Blockchain* blockchain, PeerManager* peerManager);

    // Initiates recovery if necessary
    bool attemptRecovery(const std::string& expectedTipHash);

private:
    Blockchain* blockchain_;
    PeerManager* peerManager_;

    int findRollbackHeight(const std::string& validHash);
    bool fetchAndApplyBlocksFromHeight(int startHeight);
    bool validateBlock(const Block& block);
};

#endif // SYNC_RECOVERY_H
