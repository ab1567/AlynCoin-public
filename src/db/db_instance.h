#ifndef DB_INSTANCE_H
#define DB_INSTANCE_H

#include "rocksdb_wrapper.h"
#include "db_paths.h"

namespace DB {
    extern RocksDBWrapper* instance;
    extern RocksDBWrapper* readonlyInstance;

    RocksDBWrapper* getInstance();
    RocksDBWrapper* getInstanceNoLock();

    void closeInstance();
    void closeReadonlyInstance();
}

#endif // DB_INSTANCE_H
