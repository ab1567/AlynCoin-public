#pragma once
#include <vector>
#include <string>
#include <sodium.h>

namespace crypto {
struct SphinxPacket {
    std::vector<uint8_t> header;
    std::vector<uint8_t> payload;
};

SphinxPacket createPacket(const std::vector<uint8_t>& payload,
                          const std::vector<std::string>& route,
                          const std::vector<std::vector<uint8_t>>& secrets);

bool peelPacket(const SphinxPacket& pkt, const std::vector<uint8_t>& key,
                std::string* nextHop, SphinxPacket* inner);
}
