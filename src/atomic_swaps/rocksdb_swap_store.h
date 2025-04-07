#ifndef ROCKSDB_SWAP_STORE_H
#define ROCKSDB_SWAP_STORE_H

#include <rocksdb/db.h>
#include <rocksdb/utilities/transaction_db.h>
#include <mutex>
#include <string>
#include <vector>
#include <optional>

#include "atomic_swap.h"  // ✅ Needed for AtomicSwap and AtomicSwapStore

class RocksDBAtomicSwapStore : public AtomicSwapStore {
public:
    explicit RocksDBAtomicSwapStore(const std::string& dbPath);
    ~RocksDBAtomicSwapStore();

    RocksDBAtomicSwapStore(const RocksDBAtomicSwapStore&) = delete;
    RocksDBAtomicSwapStore& operator=(const RocksDBAtomicSwapStore&) = delete;

    bool saveSwap(const AtomicSwap& swap) override;
    bool updateSwap(const AtomicSwap& swap) override;
    std::optional<AtomicSwap> loadSwap(const std::string& uuid) override;
    std::vector<AtomicSwap> getAllSwaps();

private:
    rocksdb::TransactionDB* db;
    rocksdb::TransactionDBOptions txn_options;
    rocksdb::Options options;
    std::mutex mtx;

    std::string makeKey(const std::string& id) const {
        return "aswap:" + id;
    }
};

#endif // ROCKSDB_SWAP_STORE_H
