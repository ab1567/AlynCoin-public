#ifndef RUST_BINDINGS_H
#define RUST_BINDINGS_H

#include <cstddef>   // For size_t
#include <cstdint>   // For uint8_t

#ifdef __cplusplus
extern "C" {
#endif

// Generates a zk-STARK proof from a byte-based seed
char* generate_proof_bytes(const char* seed, size_t len);

// Verifies a zk-STARK proof given the seed and expected result
bool verify_proof_ffi(const char* proof, const char* seed, const char* result);

// Result type for recursive proof
typedef struct {
    uint8_t* data;
    size_t len;
} RecursiveProofResult;

// Composes a recursive zk-STARK proof from inner proof and hash
RecursiveProofResult compose_recursive_proof_ffi(const uint8_t* proof, size_t len, const uint8_t* hash);

#ifdef __cplusplus
}
#endif

#endif // RUST_BINDINGS_H
