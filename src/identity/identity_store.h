#pragma once
#include <rocksdb/db.h>
#include <mutex>
#include <optional>
#include "identity.h"

class IdentityStore {
public:
    IdentityStore();  // No path param needed; uses DBPaths
    ~IdentityStore();

    bool save(const ZkIdentity& id);
    std::optional<ZkIdentity> load(const std::string& uuid);
    std::vector<ZkIdentity> getAll();
    bool remove(const std::string& uuid);

private:
    rocksdb::DB* db;
    std::mutex mtx;
};
