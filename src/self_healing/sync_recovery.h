#ifndef SYNC_RECOVERY_H
#define SYNC_RECOVERY_H

#include <string>
#include <mutex>
#include <unordered_set>

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
    std::mutex inflightMutex_;
    std::unordered_set<std::string> inflightBlocks_;

    int findRollbackHeight(const std::string& validHash);
    bool fetchAndApplyBlocksFromHeight(int startHeight);
    bool validateBlock(const Block& block);
    bool markBlockInFlight(const std::string& hash);
    void unmarkBlockInFlight(const std::string& hash);
};

#endif // SYNC_RECOVERY_H
