#pragma once
#include <string>
#include <vector>
#include <atomic>
#include <mutex>
#include <sstream>
namespace metrics {
struct Gauge {
    std::string name;
    std::vector<std::string> labels;
    std::atomic<double> value{0};
    Gauge(const std::string& n, std::initializer_list<std::string> l = {}) : name(n), labels(l) {}
};
extern Gauge chain_height;
extern Gauge orphan_pool_size;
extern Gauge rx_queue_depth;
extern Gauge peer_count;
extern Gauge reorg_depth;
extern std::mutex gaugeMutex;
std::string toPrometheus();
}
