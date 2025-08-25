#include "wallet_crypto.h"
#include <sodium.h>
#include <fstream>
#include <cstring>

namespace WalletCrypto {
static bool ensureSodium() {
    static bool initialised = (sodium_init() >= 0);
    return initialised;
}

bool encryptToFile(const std::string &path,
                   const std::vector<unsigned char> &plaintext,
                   const std::string &passphrase,
                   const std::string &profile,
                   uint8_t algId) {
    if (!ensureSodium()) return false;
    FileHeader hdr{};
    std::memcpy(hdr.magic, "ACWK", 4);
    hdr.version = 1;
    hdr.alg_id = algId;
    hdr.mem_mib = 256;   // default interactive profile
    hdr.time_cost = 3;
    std::memset(hdr.profile, 0, sizeof(hdr.profile));
    if (profile.size() < sizeof(hdr.profile))
        std::memcpy(hdr.profile, profile.c_str(), profile.size());
    randombytes_buf(hdr.salt, sizeof hdr.salt);
    randombytes_buf(hdr.nonce, sizeof hdr.nonce);
    unsigned char key[32];
    if (crypto_pwhash(key, sizeof key,
                      passphrase.data(), passphrase.size(),
                      hdr.salt,
                      hdr.time_cost,
                      (uint64_t)hdr.mem_mib * 1024 * 1024,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        return false;
    }
    std::vector<unsigned char> cipher(plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long clen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(cipher.data(), &clen,
                                                   plaintext.data(), plaintext.size(),
                                                   nullptr, 0, nullptr,
                                                   hdr.nonce, key) != 0) {
        sodium_memzero(key, sizeof key);
        return false;
    }
    sodium_memzero(key, sizeof key);
    std::ofstream out(path, std::ios::binary);
    if (!out) return false;
    out.write(reinterpret_cast<char*>(&hdr), sizeof hdr);
    out.write(reinterpret_cast<char*>(cipher.data()), clen);
    out.close();
    return true;
}

bool decryptFromFile(const std::string &path,
                     std::vector<unsigned char> &out,
                     const std::string &passphrase) {
    if (!ensureSodium()) return false;
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    FileHeader hdr{};
    in.read(reinterpret_cast<char*>(&hdr), sizeof hdr);
    if (std::memcmp(hdr.magic, "ACWK", 4) != 0) {
        return false;
    }
    std::vector<unsigned char> cipher((std::istreambuf_iterator<char>(in)), {});
    unsigned char key[32];
    if (crypto_pwhash(key, sizeof key,
                      passphrase.data(), passphrase.size(),
                      hdr.salt,
                      hdr.time_cost,
                      (uint64_t)hdr.mem_mib * 1024 * 1024,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        return false;
    }
    out.resize(cipher.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long mlen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(out.data(), &mlen,
                                                   nullptr,
                                                   cipher.data(), cipher.size(),
                                                   nullptr, 0,
                                                   hdr.nonce, key) != 0) {
        sodium_memzero(key, sizeof key);
        return false;
    }
    out.resize(mlen);
    sodium_memzero(key, sizeof key);
    return true;
}
} // namespace WalletCrypto
