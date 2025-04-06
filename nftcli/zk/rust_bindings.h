#ifndef RUST_BINDINGS_H
#define RUST_BINDINGS_H

#ifdef __cplusplus
extern "C" {
#endif

// Generates a zk-STARK proof from a byte-based seed
char* generate_proof_bytes(const char* seed, size_t len);

// Verifies a zk-STARK proof given the seed and expected result
bool verify_proof(const char* proof, const char* seed, const char* result);

#ifdef __cplusplus
}
#endif

#endif // RUST_BINDINGS_H
