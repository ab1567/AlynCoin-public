#ifndef EXPLORER_DB_H
#define EXPLORER_DB_H

#include <string>
#include <json/json.h>
#include <rocksdb/db.h>
#include <rocksdb/options.h>
#include <rocksdb/slice.h>
#include <rocksdb/iterator.h>

class ExplorerDB {
private:
    std::string dbPath;
    rocksdb::DB* db;

public:
    explicit ExplorerDB(const std::string& db_path);
    ~ExplorerDB();

    // ===== Blocks =====
    Json::Value getBlockByHash(const std::string& blockHash);
    Json::Value getBlockByHeight(int height);
    Json::Value getLatestBlock();

    // ===== Transactions =====
    Json::Value getTransactionByHash(const std::string& txHash);
    Json::Value getTransactionsByAddress(const std::string& address);

    // ===== Blockchain Stats =====
    Json::Value getBlockchainStats();

    // ===== Balances =====
    double getBalance(const std::string& address);
};

#endif // EXPLORER_DB_H
