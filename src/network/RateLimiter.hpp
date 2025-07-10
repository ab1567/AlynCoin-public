#pragma once
#include <unordered_map>
#include <string>
#include <mutex>
#include <chrono>
#include <algorithm>
#include <cstdint>

class RateLimiter {
    struct Bucket {
        size_t tokens{MAX_TOKENS};
        std::chrono::steady_clock::time_point last{std::chrono::steady_clock::now()};
    };
    std::unordered_map<std::string, Bucket> buckets;
    std::mutex mtx;

    static void refill(Bucket &b) {
        auto now = std::chrono::steady_clock::now();
        double elapsed = std::chrono::duration<double>(now - b.last).count();
        b.last = now;
        size_t add = static_cast<size_t>(elapsed * REFILL_RATE);
        if (add > 0) {
            b.tokens = std::min<size_t>(MAX_TOKENS, b.tokens + add);
        }
    }

public:
    static constexpr size_t MAX_TOKENS   = 8 * 1024;   // 8 MB burst
    static constexpr size_t REFILL_RATE  = 128;        // 128 KB/s

    static inline bool isCheap(uint8_t t) {
        return t == 1   // Handshake
            || t == 2   // Ping
            || t == 255 // Small control frames
            ;
    }

    bool consume(const std::string &peer, uint8_t frameType, size_t bytes) {
        if (isCheap(frameType)) return true;
        std::lock_guard<std::mutex> lock(mtx);
        auto &b = buckets[peer];
        refill(b);
        size_t needed = std::max<size_t>(1, bytes / 1024);
        if (b.tokens < needed) return false;
        b.tokens -= needed;
        return true;
    }
};
