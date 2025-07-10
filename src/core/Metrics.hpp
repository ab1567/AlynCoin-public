#pragma once
#include <atomic>
namespace Metrics {
inline std::atomic<size_t> pending_block_verifications{0};
inline std::atomic<size_t> broadcast_queue_len{0};
inline std::atomic<size_t> orphan_pool_size{0};
}
