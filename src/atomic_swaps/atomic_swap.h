#ifndef ATOMIC_SWAP_H
#define ATOMIC_SWAP_H

#include <string>
#include <optional>
#include <ctime>
#include <vector>
#include <sstream>
#include <cstdint>

// -------------------- Enum for Swap State --------------------
enum class SwapState {
    INITIATED,
    REDEEMED,
    REFUNDED,
    EXPIRED,
    INVALID
};

// -------------------- AtomicSwap Struct --------------------
struct AtomicSwap {
    std::string uuid;
    std::string senderAddress;
    std::string receiverAddress;
    uint64_t amount;
    std::string secretHash;
    std::optional<std::string> secret;
    time_t createdAt;
    time_t expiresAt;
    SwapState state;

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

// -------------------- SwapStore Interface --------------------
class AtomicSwapStore {
public:
    virtual bool saveSwap(const AtomicSwap& swap) = 0;
    virtual std::optional<AtomicSwap> loadSwap(const std::string& uuid) = 0;
    virtual bool updateSwap(const AtomicSwap& swap) = 0;
    virtual ~AtomicSwapStore() {}
};

#endif // ATOMIC_SWAP_H
