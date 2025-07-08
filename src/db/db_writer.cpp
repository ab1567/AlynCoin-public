#include "db_writer.h"

DBWriter* g_dbWriter = nullptr;

DBWriter::DBWriter(rocksdb::DB* db) : db_(db) {
    worker_ = std::thread(&DBWriter::run, this);
}

DBWriter::~DBWriter() {
    stop_ = true;
    cv_.notify_all();
    if (worker_.joinable())
        worker_.join();
}

std::future<rocksdb::Status> DBWriter::enqueue(std::unique_ptr<rocksdb::WriteBatch> batch,
                                               const rocksdb::WriteOptions& wo) {
    auto task = new DBTask;
    task->batch = std::move(batch);
    task->wo = wo;
    std::future<rocksdb::Status> fut = task->done.get_future();
    {
        std::lock_guard<std::mutex> lock(mtx_);
        queue_.push(task);
    }
    cv_.notify_one();
    return fut;
}

void DBWriter::run() {
    while (true) {
        DBTask* t = nullptr;
        {
            std::unique_lock<std::mutex> lock(mtx_);
            cv_.wait(lock, [this]{ return stop_ || !queue_.empty(); });
            if (stop_ && queue_.empty())
                break;
            t = queue_.front();
            queue_.pop();
        }
        auto status = db_->Write(t->wo, t->batch.get());
        t->done.set_value(status);
        delete t;
    }
}
