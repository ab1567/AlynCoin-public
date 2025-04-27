#ifndef ROCKSDB_WRAPPER_H
#define ROCKSDB_WRAPPER_H

#include <rocksdb/db.h>
#include <mutex>
#include <string>
#include <vector>

class RocksDBWrapper {
public:
    RocksDBWrapper(const std::string& db_path, bool readOnly = false);
    ~RocksDBWrapper();

    bool put(const std::string& key, const std::string& value);
    bool get(const std::string& key, std::string& value);
    bool del(const std::string& key);
    bool exists(const std::string& key);
    std::vector<std::pair<std::string, std::string>> prefixScan(const std::string& prefix);
    void close();

    rocksdb::DB* getRawDB() const;

private:
    rocksdb::DB* db_;
    rocksdb::Options options_;
    std::mutex db_mutex_;
    std::string db_path_;
};

#endif // ROCKSDB_WRAPPER_H
