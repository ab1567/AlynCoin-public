#include "rocksdb_wrapper.h"
#include "rocksdb_options_utils.h"
#include <iostream>

RocksDBWrapper::RocksDBWrapper(const std::string& db_path, bool readOnly)
    : db_(nullptr), db_path_(db_path) {
    options_.create_if_missing = !readOnly;
    alyn::db::ApplyDatabaseDefaults(options_);

    rocksdb::Status status;
    if (readOnly) {
        status = rocksdb::DB::OpenForReadOnly(options_, db_path, &db_);
        if (!status.ok()) {
            std::cerr << "❌ Failed to open RocksDB in read-only mode: " << status.ToString() << std::endl;
            db_ = nullptr;
        }
    } else {
        status = rocksdb::DB::Open(options_, db_path, &db_);
        if (!status.ok()) {
            std::cerr << "❌ Failed to open RocksDB: " << status.ToString() << std::endl;
            db_ = nullptr;
        }
    }
}

RocksDBWrapper::~RocksDBWrapper() {
    close();
}

void RocksDBWrapper::close() {
    std::lock_guard<std::mutex> lock(db_mutex_);
    if (db_) {
        delete db_;
        db_ = nullptr;
    }
}

bool RocksDBWrapper::put(const std::string& key, const std::string& value) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    if (!db_) return false;
    rocksdb::Status status = db_->Put(rocksdb::WriteOptions(), key, value);
    return status.ok();
}

bool RocksDBWrapper::get(const std::string& key, std::string& value) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    if (!db_) return false;
    rocksdb::Status status = db_->Get(rocksdb::ReadOptions(), key, &value);
    return status.ok();
}

bool RocksDBWrapper::del(const std::string& key) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    if (!db_) return false;
    rocksdb::Status status = db_->Delete(rocksdb::WriteOptions(), key);
    return status.ok();
}

bool RocksDBWrapper::exists(const std::string& key) {
    std::string value;
    return get(key, value);
}

std::vector<std::pair<std::string, std::string>> RocksDBWrapper::prefixScan(const std::string& prefix) {
    std::vector<std::pair<std::string, std::string>> results;
    std::lock_guard<std::mutex> lock(db_mutex_);
    if (!db_) return results;

    rocksdb::Iterator* it = db_->NewIterator(rocksdb::ReadOptions());
    for (it->Seek(prefix); it->Valid() && it->key().starts_with(prefix); it->Next()) {
        results.emplace_back(it->key().ToString(), it->value().ToString());
    }
    delete it;
    return results;
}

rocksdb::DB* RocksDBWrapper::getRawDB() const {
    return db_;
}

