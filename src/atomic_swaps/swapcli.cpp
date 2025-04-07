#include "atomic_swap.h"
#include <iostream>
#include <map>
#include <sstream>
#include <ctime>
#include <iomanip>
#include <memory>
#include <rocksdb/db.h>
#include <rocksdb/utilities/transaction_db.h>
#include <rocksdb/utilities/transaction_db_mutex.h>
#include <rocksdb/utilities/transaction_db.h>
#include "../crypto_utils.h"
#include "../zk/winterfell_stark.h"

// RocksDB-backed implementation of AtomicSwapStore
class RocksDBAtomicSwapStore : public AtomicSwapStore {
public:
    RocksDBAtomicSwapStore(const std::string& path) {
        options.create_if_missing = true;
        rocksdb::Status s = rocksdb::TransactionDB::Open(options, txn_options, path, &db);
        if (!s.ok()) throw std::runtime_error("Failed to open RocksDB: " + s.ToString());
    }

    ~RocksDBAtomicSwapStore() {
        delete db;
    }

    bool saveSwap(const AtomicSwap& swap) override {
        std::string key = "aswap:" + swap.uuid;
        std::string value;
        serialize(swap, value);
        return db->Put(rocksdb::WriteOptions(), key, value).ok();
    }

    std::optional<AtomicSwap> loadSwap(const std::string& uuid) override {
        std::string value;
        if (!db->Get(rocksdb::ReadOptions(), "aswap:" + uuid, &value).ok())
            return std::nullopt;
        return deserialize(value);
    }

    bool updateSwap(const AtomicSwap& swap) override {
        return saveSwap(swap);
    }

private:
    rocksdb::TransactionDBOptions txn_options;
    rocksdb::Options options;
    rocksdb::TransactionDB* db;

    static void serialize(const AtomicSwap& swap, std::string& out) {
        std::ostringstream oss;
        oss << swap.uuid << '\n'
            << swap.senderAddress << '\n'
            << swap.receiverAddress << '\n'
            << swap.amount << '\n'
            << swap.secretHash << '\n'
            << (swap.secret ? *swap.secret : "") << '\n'
            << swap.createdAt << '\n'
            << swap.expiresAt << '\n'
            << static_cast<int>(swap.state) << '\n'
            << swap.zkProof << '\n'
            << Crypto::base64Encode(swap.falconSignature) << '\n'
            << Crypto::base64Encode(swap.dilithiumSignature) << '\n';
        out = oss.str();
    }

    static std::optional<AtomicSwap> deserialize(const std::string& str) {
        std::istringstream iss(str);
        AtomicSwap swap;
        std::string line;
        std::getline(iss, swap.uuid);
        std::getline(iss, swap.senderAddress);
        std::getline(iss, swap.receiverAddress);
        std::getline(iss, line); swap.amount = std::stoull(line);
        std::getline(iss, swap.secretHash);
        std::getline(iss, line); swap.secret = line.empty() ? std::nullopt : std::make_optional(line);
        std::getline(iss, line); swap.createdAt = std::stoll(line);
        std::getline(iss, line); swap.expiresAt = std::stoll(line);
        std::getline(iss, line); swap.state = static_cast<SwapState>(std::stoi(line));
        std::getline(iss, swap.zkProof);
        std::getline(iss, line); swap.falconSignature = Crypto::base64Decode(line);
        std::getline(iss, line); swap.dilithiumSignature = Crypto::base64Decode(line);
        return swap;
    }
};

// Arg parser
std::map<std::string, std::string> parseArgs(int argc, char* argv[]) {
    std::map<std::string, std::string> args;
    for (int i = 2; i < argc - 1; i += 2) {
        std::string key = argv[i];
        if (key.rfind("--", 0) == 0)
            args[key.substr(2)] = argv[i + 1];
    }
    return args;
}

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

    if (!swap.zkProof.empty()) {
        std::cout << "  zk-STARK Proof: " << swap.zkProof << "\n";
    }

    if (!swap.falconSignature.empty()) {
        std::cout << "  Falcon Signature (base64): " << Crypto::base64Encode(swap.falconSignature) << "\n";
    }

    if (!swap.dilithiumSignature.empty()) {
        std::cout << "  Dilithium Signature (base64): " << Crypto::base64Encode(swap.dilithiumSignature) << "\n";
    }
}

void printUsage() {
    std::cout << "Usage:\n"
              << "  swapcli initiate --sender SENDER --receiver RECEIVER --amount AMOUNT --hash SECRET --duration SECONDS\n"
              << "  swapcli redeem --id UUID --secret SECRET\n"
              << "  swapcli refund --id UUID\n"
              << "  swapcli get --id UUID\n"
              << "  swapcli state --id UUID\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printUsage();
        return 1;
    }

    std::string cmd = argv[1];
    auto args = parseArgs(argc, argv);

    try {
        RocksDBAtomicSwapStore store("swapdb");
        AtomicSwapManager manager(&store);

        if (cmd == "initiate") {
            std::string sender = args["sender"];
            std::string receiver = args["receiver"];
            uint64_t amount = std::stoull(args["amount"]);
            std::string hash = Crypto::hybridHash(args["hash"]);
            time_t duration = std::stoll(args["duration"]);

            auto uuid = manager.initiateSwap(sender, receiver, amount, hash, duration);
            if (uuid) std::cout << "Swap created. UUID: " << *uuid << "\n";

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
