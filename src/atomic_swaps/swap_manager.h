#ifndef ATOMIC_SWAP_MANAGER_H
#define ATOMIC_SWAP_MANAGER_H

#include "atomic_swap.h"  // ✅ for AtomicSwap, AtomicSwapStore, SwapState

class AtomicSwapManager {
public:
    explicit AtomicSwapManager(AtomicSwapStore* store);

    std::optional<std::string> initiateSwap(const std::string& sender,
                                        const std::string& receiver,
                                        uint64_t amount,
                                        const std::string& secretHash,
                                        time_t durationSeconds);
    bool redeemSwap(const std::string& uuid, const std::string& secret);
    bool refundSwap(const std::string& uuid);
    std::optional<AtomicSwap> getSwap(const std::string& uuid);
    SwapState getSwapState(const std::string& uuid);

private:
    AtomicSwapStore* store_;
};

#endif // ATOMIC_SWAP_MANAGER_H
