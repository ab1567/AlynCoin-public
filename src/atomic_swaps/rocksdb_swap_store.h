#ifndef ROCKSDB_SWAP_STORE_H
#define ROCKSDB_SWAP_STORE_H

#include <rocksdb/db.h>
#include <rocksdb/utilities/transaction_db.h>
#include <mutex>
#include <string>
#include <vector>
#include <optional>
#include "atomic_swap.h"

// RocksDB-backed implementation of AtomicSwapStore interface
class RocksDBAtomicSwapStore : public AtomicSwapStore {
public:
    explicit RocksDBAtomicSwapStore(const std::string& dbPath);
    ~RocksDBAtomicSwapStore();

    // Prevent copying
    RocksDBAtomicSwapStore(const RocksDBAtomicSwapStore&) = delete;
    RocksDBAtomicSwapStore& operator=(const RocksDBAtomicSwapStore&) = delete;

    // Save new or update existing swap
    bool saveSwap(const AtomicSwap& swap) override;
    bool updateSwap(const AtomicSwap& swap) override;

    // Load single swap by UUID
    std::optional<AtomicSwap> loadSwap(const std::string& uuid) override;

    // List all swaps stored in RocksDB
    std::vector<AtomicSwap> getAllSwaps() override;

private:
    rocksdb::TransactionDB* db;
    rocksdb::TransactionDBOptions txn_options;
    rocksdb::Options options;
    std::mutex mtx;

    std::string makeKey(const std::string& id) const {
        return "aswap:" + id;
    }

    // Internal serialization
    static void serialize(const AtomicSwap& swap, std::string& out);
    static std::optional<AtomicSwap> deserialize(const std::string& data);
};

#endif // ROCKSDB_SWAP_STORE_H
