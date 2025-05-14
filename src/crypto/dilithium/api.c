#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "sign.h"
#include "api.h"

int pqcrystals_dilithium2_ref_keypair(uint8_t *pk, uint8_t *sk) {
    return crypto_sign_keypair(pk, sk);
}

int pqcrystals_dilithium2_ref_signature(uint8_t *sig, size_t *siglen,
                                        const uint8_t *m, size_t mlen,
                                        const uint8_t *ctx, size_t ctxlen,
                                        const uint8_t *sk) {
    (void)ctx; (void)ctxlen; // Ignored in basic Dilithium2 reference
    return pqcrystals_dilithium2_ref_signature(sig, siglen, m, mlen, ctx, ctxlen, sk);
}

int pqcrystals_dilithium2_ref_verify(const uint8_t *sig, size_t siglen,
                                     const uint8_t *m, size_t mlen,
                                     const uint8_t *ctx, size_t ctxlen,
                                     const uint8_t *pk) {
    (void)ctx; (void)ctxlen;
    return pqcrystals_dilithium2_ref_verify(sig, siglen, m, mlen, ctx, ctxlen, pk);
}
