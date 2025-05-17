#include "api.h"
#include "sign.h"

extern int PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
extern int PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_signature(uint8_t *sig, size_t *siglen,
                                                          const uint8_t *m, size_t mlen,
                                                          const uint8_t *ctx, size_t ctxlen,
                                                          const uint8_t *sk);
extern int PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_verify(const uint8_t *sig, size_t siglen,
                                                       const uint8_t *m, size_t mlen,
                                                       const uint8_t *ctx, size_t ctxlen,
                                                       const uint8_t *pk);

// === Correct Dilithium2 Reference Wrappers ===
int pqcrystals_dilithium2_ref_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_keypair(pk, sk);
}

int pqcrystals_dilithium2_ref_signature(uint8_t *sig, size_t *siglen,
                                        const uint8_t *m, size_t mlen,
                                        const uint8_t *ctx, size_t ctxlen,
                                        const uint8_t *sk) {
    return PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, ctx, ctxlen, sk);
}

int pqcrystals_dilithium2_ref_verify(const uint8_t *sig, size_t siglen,
                                     const uint8_t *m, size_t mlen,
                                     const uint8_t *ctx, size_t ctxlen,
                                     const uint8_t *pk) {
    return PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, ctx, ctxlen, pk);
}

// === Stub implementations (Dilithium3 & Dilithium5) ===
int pqcrystals_dilithium3_ref_keypair(uint8_t *pk, uint8_t *sk) { return -1; }
int pqcrystals_dilithium3_ref_signature(uint8_t *sig, size_t *siglen,
                                        const uint8_t *m, size_t mlen,
                                        const uint8_t *ctx, size_t ctxlen,
                                        const uint8_t *sk) { return -1; }
int pqcrystals_dilithium3_ref_verify(const uint8_t *sig, size_t siglen,
                                     const uint8_t *m, size_t mlen,
                                     const uint8_t *ctx, size_t ctxlen,
                                     const uint8_t *pk) { return -1; }

int pqcrystals_dilithium5_ref_keypair(uint8_t *pk, uint8_t *sk) { return -1; }
int pqcrystals_dilithium5_ref_signature(uint8_t *sig, size_t *siglen,
                                        const uint8_t *m, size_t mlen,
                                        const uint8_t *ctx, size_t ctxlen,
                                        const uint8_t *sk) { return -1; }
int pqcrystals_dilithium5_ref_verify(const uint8_t *sig, size_t siglen,
                                     const uint8_t *m, size_t mlen,
                                     const uint8_t *ctx, size_t ctxlen,
                                     const uint8_t *pk) { return -1; }
