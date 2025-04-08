#include "swap_manager.h"
#include "rocksdb_swap_store.h"
#include "proto_utils.h"
#include "../crypto_utils.h"
#include "../zk/winterfell_stark.h"
#include "atomic_swap.h"
#include <iostream>
#include <map>
#include <string>
#include <ctime>
#include <sstream>
#include <iomanip>

// -------------------- Arg Parser --------------------
std::map<std::string, std::string> parseArgs(int argc, char* argv[]) {
    std::map<std::string, std::string> args;
    for (int i = 2; i < argc - 1; i += 2) {
        std::string key = argv[i];
        if (key.rfind("--", 0) == 0)
            args[key.substr(2)] = argv[i + 1];
    }
    return args;
}

// -------------------- Print Functions --------------------
void printSwap(const AtomicSwap& swap) {
    std::cout << "Swap ID: " << swap.uuid << "\n"
              << "  Sender: " << swap.senderAddress << "\n"
              << "  Receiver: " << swap.receiverAddress << "\n"
              << "  Amount: " << swap.amount << "\n"
              << "  Secret Hash: " << swap.secretHash << "\n"
              << "  Secret: " << (swap.secret ? *swap.secret : "(not revealed)") << "\n"
              << "  Created: " << std::ctime(&swap.createdAt)
              << "  Expires: " << std::ctime(&swap.expiresAt)
              << "  State: " << static_cast<int>(swap.state) << "\n";

    if (swap.zkProof && !swap.zkProof->empty()) {
        std::cout << "  zk-STARK Proof: " << *swap.zkProof << "\n";
    }

    if (swap.falconSignature && !swap.falconSignature->empty()) {
        std::cout << "  Falcon Signature (base64): " << Crypto::base64Encode(*swap.falconSignature) << "\n";
    }

    if (swap.dilithiumSignature && !swap.dilithiumSignature->empty()) {
        std::cout << "  Dilithium Signature (base64): " << Crypto::base64Encode(*swap.dilithiumSignature) << "\n";
    }
}

void printUsage() {
    std::cout << "Usage:\n"
              << "  swapcli initiate --sender SENDER --receiver RECEIVER --amount AMOUNT --hash SECRET --duration SECONDS\n"
              << "  swapcli redeem --id UUID --secret SECRET\n"
              << "  swapcli refund --id UUID\n"
              << "  swapcli get --id UUID\n"
              << "  swapcli state --id UUID\n"
              << "  swapcli interactive  [ Launch interactive swap menu ]\n";
}

// -------------------- Interactive Menu --------------------
void interactiveSwap(AtomicSwapManager& manager) {
    std::string sender, receiver, secret, durationStr;
    uint64_t amount = 0;
    time_t duration = 0;

    std::cout << "\n[ AtomicSwap Interactive Mode ]\n";

    std::cout << "Sender address: ";
    std::getline(std::cin, sender);

    std::cout << "Receiver address: ";
    std::getline(std::cin, receiver);

    std::cout << "Amount to swap: ";
    std::string amountStr;
    std::getline(std::cin, amountStr);

    try {
        amount = std::stoull(amountStr);
    } catch (...) {
        std::cerr << "❌ Invalid amount format.\n";
        return;
    }

    std::cout << "Secret (preimage): ";
    std::getline(std::cin, secret);

    std::cout << "Duration (in seconds): ";
    std::getline(std::cin, durationStr);
    try {
        duration = std::stoll(durationStr);
    } catch (...) {
        std::cerr << "❌ Invalid duration format.\n";
        return;
    }

    std::string secretHash = Crypto::hybridHash(secret);
    std::cout << "Generated secret hash: " << secretHash << "\n";

    auto uuid = manager.initiateSwap(sender, receiver, amount, secretHash, duration);
    if (uuid) {
        std::cout << "\n✅ Swap created successfully!\nUUID: " << *uuid << "\n";
    } else {
        std::cerr << "❌ Failed to create swap.\n";
    }
}

// -------------------- Main --------------------
int main(int argc, char* argv[]) {
    if (argc < 2) {
        printUsage();
        return 1;
    }

    std::string cmd = argv[1];
    auto args = parseArgs(argc, argv);

    try {
        std::shared_ptr<AtomicSwapStore> store = std::make_shared<RocksDBAtomicSwapStore>("swapdb");
        AtomicSwapManager manager(store.get());

        if (cmd == "initiate") {
            std::string sender = args["sender"];
            std::string receiver = args["receiver"];
            std::string rawAmount = args["amount"];
            std::string hashInput = args["hash"];
            std::string rawDuration = args["duration"];

            uint64_t amount = 0;
            time_t duration = 0;

            try {
                amount = std::stoull(rawAmount);
                duration = std::stoll(rawDuration);
            } catch (...) {
                std::cerr << "❌ Invalid amount or duration format.\n";
                return 1;
            }

            std::string hash = Crypto::hybridHash(hashInput);
            auto uuid = manager.initiateSwap(sender, receiver, amount, hash, duration);
            if (uuid) std::cout << "Swap created. UUID: " << *uuid << "\n";

        } else if (cmd == "interactive") {
            interactiveSwap(manager);

        } else if (cmd == "redeem") {
            if (manager.redeemSwap(args["id"], args["secret"])) {
                std::cout << "Swap successfully redeemed.\n";
            }

        } else if (cmd == "refund") {
            if (manager.refundSwap(args["id"])) {
                std::cout << "Swap refunded.\n";
            }

        } else if (cmd == "get") {
            auto swap = manager.getSwap(args["id"]);
            if (swap) printSwap(*swap);
            else std::cout << "Swap not found.\n";

        } else if (cmd == "state") {
            SwapState state = manager.getSwapState(args["id"]);
            std::cout << "Swap state: " << static_cast<int>(state) << "\n";

        } else {
            printUsage();
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
