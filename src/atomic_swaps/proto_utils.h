#ifndef PROTO_UTILS_H
#define PROTO_UTILS_H

#include <string>
#include "../proto/atomic_swap.pb.h"

inline bool serializeSwap(const AtomicSwap& swap, std::string& out) {
    return swap.SerializeToString(&out);
}

inline bool deserializeSwap(const std::string& data, AtomicSwap& out) {
    return out.ParseFromString(data);
}

#endif // PROTO_UTILS_H
