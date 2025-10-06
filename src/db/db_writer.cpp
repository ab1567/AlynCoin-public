#include "db_writer.h"

#include <utility>

DBWriter* g_dbWriter = nullptr;

DBWriter::DBWriter(rocksdb::DB* db) : db_(db) {
    worker_ = std::thread(&DBWriter::run, this);
}

DBWriter::~DBWriter() {
    stop();
}

void DBWriter::stop() {
    bool expected = false;
    if (!stop_.compare_exchange_strong(expected, true))
        return;
    cv_.notify_all();
    if (worker_.joinable())
        worker_.join();

    std::deque<std::unique_ptr<DBTask>> remaining;
    {
        std::lock_guard<std::mutex> lock(mtx_);
        remaining.swap(queue_);
    }
    for (auto &task : remaining) {
        if (!task)
            continue;
        task->done.set_value(rocksdb::Status::Aborted("DBWriter stopped"));
    }
    db_.store(nullptr, std::memory_order_release);
}

void DBWriter::setDatabase(rocksdb::DB* db) {
    db_.store(db, std::memory_order_release);
}

std::future<rocksdb::Status> DBWriter::enqueue(std::unique_ptr<rocksdb::WriteBatch> batch,
                                               const rocksdb::WriteOptions& wo) {
    if (!batch) {
        std::promise<rocksdb::Status> rejected;
        auto fut = rejected.get_future();
        rejected.set_value(rocksdb::Status::InvalidArgument("empty write batch"));
        return fut;
    }

    auto task = std::make_unique<DBTask>();
    task->batch = std::move(batch);
    task->wo = wo;
    std::future<rocksdb::Status> fut = task->done.get_future();
    bool enqueueOk = true;
    {
        std::lock_guard<std::mutex> lock(mtx_);
        if (stop_.load(std::memory_order_acquire)) {
            enqueueOk = false;
        } else {
            queue_.push_back(std::move(task));
        }
    }

    if (!enqueueOk) {
        task->done.set_value(rocksdb::Status::Aborted("DBWriter stopped"));
        return fut;
    }

    cv_.notify_one();
    return fut;
}

void DBWriter::run() {
    while (true) {
        std::unique_ptr<DBTask> task;
        {
            std::unique_lock<std::mutex> lock(mtx_);
            cv_.wait(lock, [this] {
                return stop_.load(std::memory_order_acquire) || !queue_.empty();
            });
            if (queue_.empty()) {
                if (stop_.load(std::memory_order_acquire))
                    break;
                continue;
            }
            task = std::move(queue_.front());
            queue_.pop_front();
        }

        if (!task)
            continue;

        rocksdb::DB* db = db_.load(std::memory_order_acquire);
        rocksdb::Status status;
        if (!db) {
            status = rocksdb::Status::InvalidArgument("database unavailable");
        } else {
            status = db->Write(task->wo, task->batch.get());
        }
        task->done.set_value(status);
    }

    std::deque<std::unique_ptr<DBTask>> remaining;
    {
        std::lock_guard<std::mutex> lock(mtx_);
        remaining.swap(queue_);
    }
    for (auto &pending : remaining) {
        if (!pending)
            continue;
        pending->done.set_value(rocksdb::Status::Aborted("DBWriter stopped"));
    }
}
