#include "atomic_swap.h"
#include "../crypto_utils.h"
#include "../zk/winterfell_stark.h"
#include <chrono>
#include <iomanip>
#include <sstream>

AtomicSwapManager::AtomicSwapManager(AtomicSwapStore* store) : store_(store) {}

std::optional<std::string> AtomicSwapManager::initiateSwap(const std::string& sender,
                                                           const std::string& receiver,
                                                           uint64_t amount,
                                                           const std::string& secretHash,
                                                           time_t durationSeconds) {
    std::string uuid = "SWAP-" + Crypto::generateRandomHex(12);

    AtomicSwap swap;
    swap.uuid = uuid;
    swap.senderAddress = sender;
    swap.receiverAddress = receiver;
    swap.amount = amount;
    swap.secretHash = Crypto::hybridHash(secretHash);  // ✅ use hybrid hash
    swap.secret = std::nullopt;
    swap.createdAt = std::time(nullptr);
    swap.expiresAt = swap.createdAt + durationSeconds;
    swap.state = SwapState::INITIATED;
    swap.zkProof = "";
    swap.falconSignature = {};
    swap.dilithiumSignature = {};

    if (!store_->saveSwap(swap)) {
        std::cerr << "[AtomicSwap] Failed to save new swap.\n";
        return std::nullopt;
    }

    std::cout << "[AtomicSwap] Swap initiated.\n";
    std::cout << swap.toString() << "\n";
    return uuid;
}

bool AtomicSwapManager::redeemSwap(const std::string& uuid, const std::string& secret) {
    auto opt = store_->loadSwap(uuid);
    if (!opt.has_value()) {
        std::cerr << "[AtomicSwap] Cannot redeem. Swap not found.\n";
        return false;
    }

    AtomicSwap swap = opt.value();

    if (swap.state != SwapState::INITIATED) {
        std::cerr << "[AtomicSwap] Cannot redeem. Swap not in INITIATED state.\n";
        return false;
    }

    std::string expectedHash = Crypto::hybridHash(secret);
    if (expectedHash != swap.secretHash) {
        std::cerr << "[AtomicSwap] Invalid secret provided.\n";
        return false;
    }

    // ✅ Load sender Falcon/Dilithium keys
    auto falKeys = Crypto::loadFalconKeys(swap.senderAddress);
    auto dilKeys = Crypto::loadDilithiumKeys(swap.senderAddress);

    if (falKeys.privateKey.empty() || dilKeys.privateKey.empty()) {
        std::cerr << "[AtomicSwap] Missing signing keys for sender.\n";
        return false;
    }

    std::vector<unsigned char> secretBytes = Crypto::stringToBytes(secret);
    swap.falconSignature = Crypto::signWithFalcon(secretBytes, falKeys.privateKey);
    swap.dilithiumSignature = Crypto::signWithDilithium(secretBytes, dilKeys.privateKey);

    if (swap.falconSignature.empty() || swap.dilithiumSignature.empty()) {
        std::cerr << "[AtomicSwap] Signature generation failed.\n";
        return false;
    }

    // ✅ Generate zk-STARK proof of redemption
    std::string seed = swap.senderAddress + swap.receiverAddress + std::to_string(swap.amount) + secret;
    swap.zkProof = WinterfellStark::generateTransactionProof(
        swap.senderAddress, swap.receiverAddress, static_cast<double>(swap.amount), swap.createdAt
    );

    swap.secret = secret;
    swap.state = SwapState::REDEEMED;

    return store_->updateSwap(swap);
}

bool AtomicSwapManager::refundSwap(const std::string& uuid) {
    auto opt = store_->loadSwap(uuid);
    if (!opt.has_value()) {
        std::cerr << "[AtomicSwap] Cannot refund. Swap not found.\n";
        return false;
    }

    AtomicSwap swap = opt.value();
    if (swap.state != SwapState::INITIATED) {
        std::cerr << "[AtomicSwap] Cannot refund. Invalid state.\n";
        return false;
    }

    time_t now = std::time(nullptr);
    if (now < swap.expiresAt) {
        std::cerr << "[AtomicSwap] Cannot refund yet. Wait until expiration.\n";
        return false;
    }

    swap.state = SwapState::REFUNDED;
    return store_->updateSwap(swap);
}

std::optional<AtomicSwap> AtomicSwapManager::getSwap(const std::string& uuid) {
    return store_->loadSwap(uuid);
}

SwapState AtomicSwapManager::getSwapState(const std::string& uuid) {
    auto opt = store_->loadSwap(uuid);
    return opt.has_value() ? opt->state : SwapState::INVALID;
}
