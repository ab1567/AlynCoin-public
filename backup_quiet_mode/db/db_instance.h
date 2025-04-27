#ifndef DB_INSTANCE_H
#define DB_INSTANCE_H

#include "rocksdb_wrapper.h"
#include "db_paths.h"

namespace DB {
    static RocksDBWrapper* instance = nullptr;
    static RocksDBWrapper* readonlyInstance = nullptr;

    // Regular full access (read/write)
    inline RocksDBWrapper* getInstance() {
        if (!instance) {
            static RocksDBWrapper wrapper(DBPaths::getBlockchainDB());
            instance = &wrapper;
        }
        return instance;
    }

    // Read-only safe access (for NFT CLI or stats)
    inline RocksDBWrapper* getInstanceNoLock() {
        if (!readonlyInstance) {
            static RocksDBWrapper wrapper(DBPaths::getBlockchainDB(), /* readOnly */ true);
            readonlyInstance = &wrapper;
        }
        return readonlyInstance;
    }

    // Close DB instance to release lock (for subprocess calls)
    inline void closeInstance() {
        if (instance) {
            instance->close();
            instance = nullptr;
        }
    }

    inline void closeReadonlyInstance() {
        if (readonlyInstance) {
            readonlyInstance->close();
            readonlyInstance = nullptr;
        }
    }
}

#endif // DB_INSTANCE_H
