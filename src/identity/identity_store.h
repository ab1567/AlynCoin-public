#pragma once
#include <rocksdb/db.h>
#include <mutex>
#include "identity.h"

class IdentityStore {
public:
    explicit IdentityStore(const std::string& path);
    ~IdentityStore();

    bool save(const ZkIdentity& id);
    std::optional<ZkIdentity> load(const std::string& uuid);
    std::vector<ZkIdentity> getAll();
    bool remove(const std::string& uuid);

private:
    rocksdb::DB* db;
    std::mutex mtx;
};
