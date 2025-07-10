#pragma once
#include <unordered_map>
#include <string>
#include <mutex>
#include <chrono>

class RateLimiter {
    struct Bucket {
        double tokens{0};
        std::chrono::steady_clock::time_point last{std::chrono::steady_clock::now()};
    };
    std::unordered_map<std::string, Bucket> buckets;
    double rate; // tokens per second
    double burst;
    std::mutex mtx;
public:
    RateLimiter(double r=50.0, double b=100.0) : rate(r), burst(b) {}

    bool allow(const std::string &peer) {
        std::lock_guard<std::mutex> lock(mtx);
        auto &b = buckets[peer];
        auto now = std::chrono::steady_clock::now();
        double elapsed = std::chrono::duration<double>(now - b.last).count();
        b.last = now;
        b.tokens = std::min(burst, b.tokens + elapsed * rate);
        if (b.tokens >= 1.0) {
            b.tokens -= 1.0;
            return true;
        }
        return false;
    }
};
