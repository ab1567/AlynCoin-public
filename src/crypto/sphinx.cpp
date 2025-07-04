#include "crypto/sphinx.h"
#include <sodium.h>
#include <cstring>

namespace crypto {

SphinxPacket createPacket(const std::vector<uint8_t>& payload,
                          const std::vector<std::vector<uint8_t>>& route,
                          const std::vector<uint8_t>& sharedSecret) {
    SphinxPacket pkt;
    if (sodium_init() < 0) return pkt;
    pkt.header.resize(24);
    randombytes_buf(pkt.header.data(), pkt.header.size());

    pkt.payload.resize(payload.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long clen = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt(pkt.payload.data(), &clen,
                                               payload.data(), payload.size(),
                                               route.empty() ? nullptr : route[0].data(),
                                               route.empty() ? 0 : route[0].size(),
                                               nullptr, pkt.header.data(), sharedSecret.data());
    pkt.payload.resize(clen);
    return pkt;
}

bool peelPacket(const SphinxPacket& pkt, const std::vector<uint8_t>& privKey,
                std::vector<uint8_t>* nextHop,
                std::vector<uint8_t>* innerPayload) {
    if (sodium_init() < 0) return false;
    innerPayload->resize(pkt.payload.size());
    unsigned long long mlen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(innerPayload->data(), &mlen,
                                                   nullptr,
                                                   pkt.payload.data(), pkt.payload.size(),
                                                   nullptr, 0,
                                                   pkt.header.data(), privKey.data()) != 0) {
        return false;
    }
    innerPayload->resize(mlen);
    // nextHop not implemented - placeholder
    if (nextHop) nextHop->clear();
    return true;
}

} // namespace crypto
