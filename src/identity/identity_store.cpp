#include "identity_store.h"
#include "proto_utils.h"
#include "../db/db_paths.h"
#include "../db/rocksdb_options_utils.h"

IdentityStore::IdentityStore() {
    rocksdb::Options options;
    options.create_if_missing = true;
    alyn::db::ApplyDatabaseDefaults(options);
    std::string path = DBPaths::getIdentityDB();
    rocksdb::Status status = rocksdb::DB::Open(options, path, &db);
    if (!status.ok()) {
        throw std::runtime_error("Failed to open identity DB: " + status.ToString());
    }
}

IdentityStore::~IdentityStore() {
    if (db) delete db;
}

bool IdentityStore::save(const ZkIdentity& id) {
    std::string out;
    if (!serializeIdentity(id, out)) return false;
    return db->Put(rocksdb::WriteOptions(), "zkid:" + id.uuid, out).ok();
}

std::optional<ZkIdentity> IdentityStore::load(const std::string& uuid) {
    std::string value;
    rocksdb::Status status = db->Get(rocksdb::ReadOptions(), "zkid:" + uuid, &value);
    if (!status.ok()) return std::nullopt;

    ZkIdentity id;
    if (!deserializeIdentity(value, id)) return std::nullopt;
    return id;
}

bool IdentityStore::remove(const std::string& uuid) {
    return db->Delete(rocksdb::WriteOptions(), "zkid:" + uuid).ok();
}

std::vector<ZkIdentity> IdentityStore::getAll() {
    std::vector<ZkIdentity> results;
    std::unique_ptr<rocksdb::Iterator> it(db->NewIterator(rocksdb::ReadOptions()));
    for (it->Seek("zkid:"); it->Valid() && it->key().ToString().rfind("zkid:", 0) == 0; it->Next()) {
        ZkIdentity id;
        if (deserializeIdentity(it->value().ToString(), id)) {
            results.push_back(id);
        }
    }
    return results;
}
