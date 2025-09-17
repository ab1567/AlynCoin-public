#include "proto_utils.h"
#include "swap_manager.h"
#include "rocksdb_swap_store.h"
#include "swap_manager.h"
#include "../crypto_utils.h"
#include "../zk/winterfell_stark.h"
#include <iostream>
#include <chrono>
#include <ctime>

AtomicSwapManager::AtomicSwapManager(AtomicSwapStore* store) : store_(store) {}

std::optional<std::string> AtomicSwapManager::initiateSwap(const std::string& sender,
                                                           const std::string& receiver,
                                                           uint64_t amount,
                                                           const std::string& secretHash,
                                                           time_t durationSeconds) {
    auto resolvedSender = Crypto::resolveWalletKeyIdentifier(sender);
    std::string senderKeyId = resolvedSender.value_or(sender);

    auto falKeys = Crypto::loadFalconKeys(senderKeyId);
    auto dilKeys = Crypto::loadDilithiumKeys(senderKeyId);
    if (falKeys.privateKey.empty() || falKeys.publicKey.empty() ||
        dilKeys.privateKey.empty() || dilKeys.publicKey.empty()) {
        std::cerr << "[AtomicSwapManager] Missing PQ key material for sender: "
                  << sender << std::endl;
        return std::nullopt;
    }

    auto toLower = [](std::string v) {
        std::transform(v.begin(), v.end(), v.begin(), ::tolower);
        return v;
    };

    std::string canonicalSender;
    if (!dilKeys.publicKey.empty()) {
        canonicalSender = Crypto::deriveAddressFromPub(dilKeys.publicKey);
    }
    if (canonicalSender.empty() && !falKeys.publicKey.empty()) {
        canonicalSender = Crypto::deriveAddressFromPub(falKeys.publicKey);
    }
    if (canonicalSender.empty()) {
        canonicalSender = senderKeyId;
    }
    canonicalSender = toLower(canonicalSender);

    std::string canonicalReceiver = receiver;
    bool receiverResolved = false;
    if (auto resolvedReceiver = Crypto::resolveWalletKeyIdentifier(receiver)) {
        auto recvDil = Crypto::loadDilithiumKeys(*resolvedReceiver);
        auto recvFal = Crypto::loadFalconKeys(*resolvedReceiver);
        if (!recvDil.publicKey.empty()) {
            canonicalReceiver = Crypto::deriveAddressFromPub(recvDil.publicKey);
            receiverResolved = true;
        } else if (!recvFal.publicKey.empty()) {
            canonicalReceiver = Crypto::deriveAddressFromPub(recvFal.publicKey);
            receiverResolved = true;
        }
    }
    if (receiverResolved || Crypto::isLikelyHex(canonicalReceiver)) {
        canonicalReceiver = toLower(canonicalReceiver);
    }

    AtomicSwap swap;
    swap.uuid = "SWAP-" + Crypto::generateRandomHex(12);
    swap.senderAddress = canonicalSender;
    swap.receiverAddress = canonicalReceiver;
    swap.amount = amount;
    swap.secretHash = secretHash;
    swap.secret = std::nullopt;
    swap.createdAt = std::time(nullptr);
    swap.expiresAt = swap.createdAt + durationSeconds;
    swap.state = SwapState::INITIATED;

    // ✅ Canonical data for hash-based signing
    std::string canonicalData = swap.uuid + swap.senderAddress + swap.receiverAddress +
                                std::to_string(swap.amount) + swap.secretHash +
                                std::to_string(swap.createdAt) + std::to_string(swap.expiresAt);

    std::vector<uint8_t> msgHash = Crypto::sha256ToBytes(canonicalData);

    // ✅ Sign with Falcon & Dilithium using resolved key identifier
    std::vector<uint8_t> sigFal = Crypto::signWithFalcon(msgHash, falKeys.privateKey);
    std::vector<uint8_t> sigDil = Crypto::signWithDilithium(msgHash, dilKeys.privateKey);

    swap.falconSignature = sigFal; 
    swap.dilithiumSignature = sigDil;

    // ✅ Optional: zk-STARK Proof
    std::string seedHash = Crypto::blake3(canonicalData);
    swap.zkProof = WinterfellStark::generateProof(seedHash, "AtomicSwapProof", std::to_string(amount));

    bool success = store_->saveSwap(swap);
    return success ? std::optional<std::string>(swap.uuid) : std::nullopt;
}

bool AtomicSwapManager::redeemSwap(const std::string& uuid, const std::string& secret) {
    auto optSwap = store_->loadSwap(uuid);
    if (!optSwap) {
        std::cerr << "[AtomicSwapManager] Swap not found: " << uuid << "\n";
        return false;
    }

    AtomicSwap swap = *optSwap;

    if (swap.state != SwapState::INITIATED) {
        std::cerr << "[AtomicSwapManager] Swap not in redeemable state.\n";
        return false;
    }

    if (secret.empty()) {
        std::cerr << "[AtomicSwapManager] Secret is required.\n";
        return false;
    }

    time_t now = std::time(nullptr);
    if (now >= swap.expiresAt) {
        std::cerr << "[AtomicSwapManager] Swap expired.\n";
        return false;
    }

    std::string computedHash = Crypto::hybridHash(secret);
    if (computedHash != swap.secretHash) {
        std::cerr << "[AtomicSwapManager] Secret mismatch. Invalid preimage.\n";
        return false;
    }

    swap.secret = secret;
    swap.state = SwapState::REDEEMED;

    // Optional: attach zk-STARK proof for claim verification
    // swap.zkProof = WinterfellStark::generateProof(swap.senderAddress, swap.receiverAddress, swap.amount, swap.createdAt);

    return store_->updateSwap(swap);
}

bool AtomicSwapManager::refundSwap(const std::string& uuid) {
    auto optSwap = store_->loadSwap(uuid);
    if (!optSwap) {
        std::cerr << "[AtomicSwapManager] Swap not found for refund: " << uuid << "\n";
        return false;
    }

    AtomicSwap swap = *optSwap;
    time_t now = std::time(nullptr);

    if (swap.state != SwapState::INITIATED) {
        std::cerr << "[AtomicSwapManager] Swap is not refundable.\n";
        return false;
    }

    if (now < swap.expiresAt) {
        std::cerr << "[AtomicSwapManager] Too early to refund swap.\n";
        return false;
    }

    swap.state = SwapState::REFUNDED;
    return store_->updateSwap(swap);
}

std::optional<AtomicSwap> AtomicSwapManager::getSwap(const std::string& uuid) {
    return store_->loadSwap(uuid);
}

SwapState AtomicSwapManager::getSwapState(const std::string& uuid) {
    auto swap = getSwap(uuid);
    return swap ? swap->state : SwapState::INVALID;
}
