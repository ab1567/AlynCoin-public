#include "db_instance.h"

namespace DB {
    RocksDBWrapper* instance = nullptr;
    RocksDBWrapper* readonlyInstance = nullptr;

    RocksDBWrapper* getInstance() {
        if (!instance) {
            instance = new RocksDBWrapper(DBPaths::getBlockchainDB());
        }
        return instance;
    }

    RocksDBWrapper* getInstanceNoLock() {
        if (!readonlyInstance) {
            readonlyInstance = new RocksDBWrapper(DBPaths::getBlockchainDB(), /* readOnly */ true);
        }
        return readonlyInstance;
    }

    void closeInstance() {
        if (instance) {
            instance->close();
            delete instance;
            instance = nullptr;
        }
    }

    void closeReadonlyInstance() {
        if (readonlyInstance) {
            readonlyInstance->close();
            delete readonlyInstance;
            readonlyInstance = nullptr;
        }
    }
}
