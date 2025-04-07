#ifndef ATOMIC_SWAP_MANAGER_H
#define ATOMIC_SWAP_MANAGER_H

#include "atomic_swap.h"
#include "swap_store.h"
#include <optional>
#include <vector>
#include <string>

// High-level manager to coordinate atomic swaps with crypto + zk proofs
class AtomicSwapManager {
public:
    explicit AtomicSwapManager(AtomicSwapStore* store);

    // Initiate a new atomic swap
    std::optional<std::string> initiateSwap(const std::string& sender,
                                            const std::string& receiver,
                                            uint64_t amount,
                                            const std::string& secretHash,
                                            time_t durationSeconds);

    // Redeem a swap using the preimage (secret)
    bool redeemSwap(const std::string& uuid, const std::string& secret);

    // Refund an expired swap
    bool refundSwap(const std::string& uuid);

    // Fetch a swap by UUID
    std::optional<AtomicSwap> getSwap(const std::string& uuid);

    // Get current state of a swap
    SwapState getSwapState(const std::string& uuid);

private:
    AtomicSwapStore* store_;
};

#endif // ATOMIC_SWAP_MANAGER_H
