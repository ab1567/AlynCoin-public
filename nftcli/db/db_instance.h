#ifndef DB_INSTANCE_H
#define DB_INSTANCE_H

#include "rocksdb_wrapper.h"
#include "db_paths.h"

namespace DB {
    static RocksDBWrapper* instance = nullptr;

    inline RocksDBWrapper* getInstance() {
        if (!instance) {
            static RocksDBWrapper wrapper(DBPaths::getBlockchainDB());
            instance = &wrapper;
        }
        return instance;
    }
}

#endif // DB_INSTANCE_H
