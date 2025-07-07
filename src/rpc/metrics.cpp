#include "rpc/metrics.h"
#include <sstream>
namespace metrics {
Gauge chain_height{"chain_height", {"chain"}};
Gauge orphan_pool_size{"orphan_pool_size"};
Gauge rx_queue_depth{"rx_queue_depth"};
Gauge peer_count{"peer_count"};
Gauge reorg_depth{"reorg_depth"};
std::mutex gaugeMutex;
std::string toPrometheus() {
    std::lock_guard<std::mutex> lk(gaugeMutex);
    std::ostringstream os;
    os << chain_height.name << " " << chain_height.value.load() << "\n";
    os << orphan_pool_size.name << " " << orphan_pool_size.value.load() << "\n";
    os << rx_queue_depth.name << " " << rx_queue_depth.value.load() << "\n";
    os << peer_count.name << " " << peer_count.value.load() << "\n";
    os << reorg_depth.name << " " << reorg_depth.value.load() << "\n";
    return os.str();
}
} // namespace metrics
