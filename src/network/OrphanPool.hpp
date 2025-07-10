#pragma once
#include "block.h"
#include <deque>
#include <mutex>
#include <unordered_set>
#include <vector>
#include "core/Metrics.hpp"

class OrphanPool {
    std::deque<Block> pool;
    std::unordered_set<std::string> hashes;
    size_t cap;
    mutable std::mutex mtx;
public:
    explicit OrphanPool(size_t c = 5000) : cap(c) {}

    void add(const Block &blk) {
        std::lock_guard<std::mutex> lock(mtx);
        if (hashes.count(blk.getHash()))
            return;
        if (pool.size() >= cap) {
            hashes.erase(pool.front().getHash());
            pool.pop_front();
        }
        pool.push_back(blk);
        hashes.insert(blk.getHash());
        Metrics::orphan_pool_size.store(pool.size(), std::memory_order_relaxed);
    }

    std::vector<Block> popChildren(const std::string &parent) {
        std::lock_guard<std::mutex> lock(mtx);
        std::vector<Block> out;
        auto it = pool.begin();
        while (it != pool.end()) {
            if (it->getPreviousHash() == parent) {
                hashes.erase(it->getHash());
                out.push_back(*it);
                it = pool.erase(it);
            } else {
                ++it;
            }
        }
        Metrics::orphan_pool_size.store(pool.size(), std::memory_order_relaxed);
        return out;
    }

    size_t size() const {
        std::lock_guard<std::mutex> lock(mtx);
        return pool.size();
    }
    size_t capacity() const { return cap; }
};
