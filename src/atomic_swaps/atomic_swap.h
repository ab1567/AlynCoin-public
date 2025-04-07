#ifndef ATOMIC_SWAP_H
#define ATOMIC_SWAP_H

#include <sstream>
#include <string>
#include <ctime>
#include <optional>
#include <vector>
#include <cstdint>
#include <iostream>

enum class SwapState {
    INITIATED,
    REDEEMED,
    REFUNDED,
    EXPIRED,
    INVALID
};

struct AtomicSwap {
    std::string uuid;
    std::string senderAddress;
    std::string receiverAddress;
    uint64_t amount;
    std::string secretHash;  // Now using hybridHash
    std::optional<std::string> secret;
    time_t createdAt;
    time_t expiresAt;
    SwapState state;

    // New fields for quantum and zk enhancements
    std::optional<std::string> zkProof;
    std::optional<std::string> falconSignature;
    std::optional<std::string> dilithiumSignature;

    std::string toString() const {
        std::ostringstream oss;
        oss << "[AtomicSwap] UUID: " << uuid
            << "\n  Sender: " << senderAddress
            << "\n  Receiver: " << receiverAddress
            << "\n  Amount: " << amount
            << "\n  Secret Hash: " << secretHash
            << "\n  Secret: " << (secret ? *secret : "(hidden)")
            << "\n  Created: " << createdAt
            << "\n  Expires: " << expiresAt
            << "\n  State: " << static_cast<int>(state);
        if (zkProof) oss << "\n  zkProof: " << *zkProof;
        if (falconSignature) oss << "\n  FalconSig: " << *falconSignature;
        if (dilithiumSignature) oss << "\n  DilithiumSig: " << *dilithiumSignature;
        return oss.str();
    }
};

class AtomicSwapStore {
public:
    virtual bool saveSwap(const AtomicSwap& swap) = 0;
    virtual std::optional<AtomicSwap> loadSwap(const std::string& uuid) = 0;
    virtual bool updateSwap(const AtomicSwap& swap) = 0;
    virtual ~AtomicSwapStore() {}
};

class AtomicSwapManager {
public:
    AtomicSwapManager(AtomicSwapStore* store);

    std::optional<std::string> initiateSwap(const std::string& sender,
                                            const std::string& receiver,
                                            uint64_t amount,
                                            const std::string& secret,
                                            time_t durationSeconds);

    bool redeemSwap(const std::string& uuid, const std::string& secret);
    bool refundSwap(const std::string& uuid);
    std::optional<AtomicSwap> getSwap(const std::string& uuid);
    SwapState getSwapState(const std::string& uuid);

private:
    AtomicSwapStore* store_;
};

#endif // ATOMIC_SWAP_H
