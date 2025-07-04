#pragma once
#include <vector>
#include <sodium.h>

namespace crypto {
struct SphinxPacket {
    std::vector<uint8_t> header;
    std::vector<uint8_t> payload;
};

SphinxPacket createPacket(const std::vector<uint8_t>& payload,
                          const std::vector<std::vector<uint8_t>>& route,
                          const std::vector<uint8_t>& sharedSecret);

bool peelPacket(const SphinxPacket& pkt, const std::vector<uint8_t>& privKey,
                std::vector<uint8_t>* nextHop,
                std::vector<uint8_t>* innerPayload);
}
