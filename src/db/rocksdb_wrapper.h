#ifndef ROCKSDB_WRAPPER_H
#define ROCKSDB_WRAPPER_H

#include <rocksdb/db.h>
#include <mutex>
#include <string>

class RocksDBWrapper {
public:
    RocksDBWrapper(const std::string& db_path);
    ~RocksDBWrapper();

    bool put(const std::string& key, const std::string& value);
    bool get(const std::string& key, std::string& value);
    bool del(const std::string& key);
    void close();
    bool exists(const std::string& key);
    std::vector<std::pair<std::string, std::string>> prefixScan(const std::string& prefix);
private:
    rocksdb::DB* db_;
    rocksdb::Options options_;
    std::mutex db_mutex_;
};

#endif // ROCKSDB_WRAPPER_H
