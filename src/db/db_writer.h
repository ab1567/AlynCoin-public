#pragma once
#include <rocksdb/db.h>
#include <rocksdb/write_batch.h>
#include <atomic>
#include <condition_variable>
#include <deque>
#include <future>
#include <memory>
#include <mutex>
#include <thread>

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
    void stop();
    void setDatabase(rocksdb::DB* db);

private:
    void run();
    std::atomic<rocksdb::DB*> db_;
    std::deque<std::unique_ptr<DBTask>> queue_;
    std::mutex mtx_;
    std::condition_variable cv_;
    std::thread worker_;
    std::atomic<bool> stop_{false};
};

extern DBWriter* g_dbWriter;
