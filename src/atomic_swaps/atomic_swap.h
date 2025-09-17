#ifndef ATOMIC_SWAP_H
#define ATOMIC_SWAP_H

#include <string>
#include <optional>
#include <ctime>
#include <vector>
#include <sstream>
#include <cstdint>
#include <algorithm>
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

    // ✅ Use binary signature types
    std::optional<std::vector<unsigned char>> falconSignature;
    std::optional<std::vector<unsigned char>> dilithiumSignature;

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
        if (falconSignature) oss << "\n  FalconSig (hex): " << Crypto::toHex(*falconSignature);
        if (dilithiumSignature) oss << "\n  DilithiumSig (hex): " << Crypto::toHex(*dilithiumSignature);
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

// -------------------- Signature Verification --------------------
inline bool verifySwapSignature(const AtomicSwap& swap) {
    if (!swap.falconSignature || !swap.dilithiumSignature) return false;

    std::string canonicalData = swap.uuid + swap.senderAddress + swap.receiverAddress +
                                std::to_string(swap.amount) + swap.secretHash +
                                std::to_string(swap.createdAt) + std::to_string(swap.expiresAt);

    std::vector<uint8_t> msgHash = Crypto::sha256ToBytes(canonicalData);

    auto toLower = [](std::string v) {
        std::transform(v.begin(), v.end(), v.begin(), ::tolower);
        return v;
    };

    std::string senderCanonical = toLower(swap.senderAddress);

    std::vector<uint8_t> pubFal = Crypto::getPublicKeyFalcon(senderCanonical);
    std::vector<uint8_t> pubDil = Crypto::getPublicKeyDilithium(senderCanonical);

    if (pubFal.empty() || pubDil.empty()) {
        std::cerr << "❌ [verifySwapSignature] Missing PQ public keys for sender: "
                  << swap.senderAddress << "\n";
        return false;
    }

    std::string expectedFal = toLower(Crypto::deriveAddressFromPub(pubFal));
    std::string expectedDil = toLower(Crypto::deriveAddressFromPub(pubDil));

    if (senderCanonical != expectedFal && senderCanonical != expectedDil) {
        std::cerr << "❌ ERR_ADDR_MISMATCH (swap): sender=" << swap.senderAddress
                  << " expected(any)=[" << expectedDil << "," << expectedFal << "]\n";
        return false;
    }

    return Crypto::verifyWithFalcon(msgHash, *swap.falconSignature, pubFal) &&
           Crypto::verifyWithDilithium(msgHash, *swap.dilithiumSignature, pubDil);
}

#endif // ATOMIC_SWAP_H
