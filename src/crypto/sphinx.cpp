#include "crypto/sphinx.h"
#include <sodium.h>
#include <cstring>
#include <string>

namespace crypto {

SphinxPacket createPacket(const std::vector<uint8_t>& payload,
                          const std::vector<std::string>& route,
                          const std::vector<std::vector<uint8_t>>& secrets) {
    SphinxPacket inner;
    if (sodium_init() < 0) return inner;
    if (route.size() != secrets.size() || route.empty())
        return inner;

    inner.header.resize(24);
    randombytes_buf(inner.header.data(), 24);
    inner.header.push_back(0);
    inner.payload.resize(payload.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long clen = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt(inner.payload.data(), &clen,
                                               payload.data(), payload.size(),
                                               nullptr, 0, nullptr,
                                               inner.header.data(), secrets.back().data());
    inner.payload.resize(clen);

    for (int i = static_cast<int>(route.size()) - 2; i >= 0; --i) {
        SphinxPacket layer;
        layer.header.resize(24);
        randombytes_buf(layer.header.data(), 24);
        const std::string& nh = route[i + 1];
        layer.header.push_back(static_cast<uint8_t>(nh.size()));
        layer.header.insert(layer.header.end(), nh.begin(), nh.end());

        std::vector<uint8_t> plain;
        plain.insert(plain.end(), inner.header.begin(), inner.header.end());
        plain.insert(plain.end(), inner.payload.begin(), inner.payload.end());

        layer.payload.resize(plain.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
        unsigned long long clen2 = 0;
        crypto_aead_xchacha20poly1305_ietf_encrypt(layer.payload.data(), &clen2,
                                                   plain.data(), plain.size(),
                                                   nullptr, 0, nullptr,
                                                   layer.header.data(), secrets[i].data());
        layer.payload.resize(clen2);
        inner = layer;
    }
    return inner;
}

bool peelPacket(const SphinxPacket& pkt, const std::vector<uint8_t>& key,
                std::string* nextHop, SphinxPacket* inner) {
    if (sodium_init() < 0) return false;
    if (pkt.header.size() < 25) return false;
    uint8_t len = pkt.header[24];
    if (pkt.header.size() < 25 + len) return false;
    if (nextHop)
        *nextHop = std::string(pkt.header.begin() + 25,
                               pkt.header.begin() + 25 + len);

    std::vector<uint8_t> plain(pkt.payload.size());
    unsigned long long mlen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(plain.data(), &mlen,
                                                   nullptr,
                                                   pkt.payload.data(), pkt.payload.size(),
                                                   nullptr, 0,
                                                   pkt.header.data(), key.data()) != 0)
        return false;
    plain.resize(mlen);
    if (inner) {
        if (plain.size() < 25) {
            inner->header.clear();
            inner->payload = plain;
        } else {
            uint8_t innerLen = plain[24];
            size_t headerSize = 25 + innerLen;
            if (plain.size() < headerSize) return false;
            inner->header.assign(plain.begin(), plain.begin() + headerSize);
            inner->payload.assign(plain.begin() + headerSize, plain.end());
        }
    }
    return true;
}

} // namespace crypto
