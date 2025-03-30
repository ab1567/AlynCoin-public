#include "rocksdb_wrapper.h"
#include <iostream>

RocksDBWrapper::RocksDBWrapper(const std::string& db_path) {
    options_.create_if_missing = true;
    rocksdb::Status status = rocksdb::DB::Open(options_, db_path, &db_);
    if (!status.ok()) {
        std::cerr << "Failed to open RocksDB: " << status.ToString() << std::endl;
        db_ = nullptr;
    }
}

RocksDBWrapper::~RocksDBWrapper() {
    close();
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

void RocksDBWrapper::close() {
    std::lock_guard<std::mutex> lock(db_mutex_);
    if (db_) {
        delete db_;
        db_ = nullptr;
    }
}
bool RocksDBWrapper::exists(const std::string& key) {
    std::string value;
    rocksdb::Status status = db_->Get(rocksdb::ReadOptions(), key, &value);
    return status.ok();
}
std::vector<std::pair<std::string, std::string>> RocksDBWrapper::prefixScan(const std::string& prefix) {
    std::vector<std::pair<std::string, std::string>> results;
    rocksdb::Iterator* it = db_->NewIterator(rocksdb::ReadOptions());

    for (it->Seek(prefix); it->Valid() && it->key().starts_with(prefix); it->Next()) {
        std::string key = it->key().ToString();
        std::string value = it->value().ToString();
        results.emplace_back(key, value);
    }

    delete it;
    return results;
}
