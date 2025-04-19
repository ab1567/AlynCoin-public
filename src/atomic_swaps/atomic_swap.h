#ifndef ATOMIC_SWAP_H
#define ATOMIC_SWAP_H

#include <string>
#include <optional>
#include <ctime>
#include <vector>
#include <sstream>
#include <cstdint>
#include "../crypto_utils.h"

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

// ---------------
inline bool verifySwapSignature(const AtomicSwap& swap) {
    std::string canonicalData = swap.uuid + swap.senderAddress + swap.receiverAddress +
                                std::to_string(swap.amount) + swap.secretHash +
                                std::to_string(swap.createdAt) + std::to_string(swap.expiresAt);

    std::vector<uint8_t> msgHash = Crypto::sha256ToBytes(canonicalData);

    std::vector<uint8_t> pubFal = Crypto::getPublicKeyFalcon(swap.senderAddress);
    std::vector<uint8_t> sigFal = Crypto::fromHex(*swap.falconSignature);

    std::vector<uint8_t> pubDil = Crypto::getPublicKeyDilithium(swap.senderAddress);
    std::vector<uint8_t> sigDil = Crypto::fromHex(*swap.dilithiumSignature);

    return Crypto::verifyWithFalcon(msgHash, sigFal, pubFal) &&
           Crypto::verifyWithDilithium(msgHash, sigDil, pubDil);
}

#endif // ATOMIC_SWAP_H
