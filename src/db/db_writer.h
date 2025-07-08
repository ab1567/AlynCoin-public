#pragma once
#include <rocksdb/db.h>
#include <rocksdb/write_batch.h>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <future>
#include <thread>
#include <atomic>

struct DBTask {
    std::unique_ptr<rocksdb::WriteBatch> batch;
    rocksdb::WriteOptions wo;
    std::promise<rocksdb::Status> done;
};

class DBWriter {
public:
    explicit DBWriter(rocksdb::DB* db);
    ~DBWriter();

    std::future<rocksdb::Status> enqueue(std::unique_ptr<rocksdb::WriteBatch> batch,
                                         const rocksdb::WriteOptions& wo = rocksdb::WriteOptions());

private:
    void run();
    rocksdb::DB* db_;
    std::queue<DBTask*> queue_;
    std::mutex mtx_;
    std::condition_variable cv_;
    std::thread worker_;
    std::atomic<bool> stop_{false};
};

extern DBWriter* g_dbWriter;
