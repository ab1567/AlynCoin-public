#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// Function to generate a zk-STARK proof
const char* generate_winterfell_proof(const char* block_hash, const char* prev_hash, const char* tx_root);

// Function to verify a zk-STARK proof
bool verify_winterfell_proof(const char* proof, const char* block_hash, const char* prev_hash, const char* tx_root);

// Rollup-specific proof generation
char* generate_rollup_proof(const char* block_hash, const char* prev_hash, const char* tx_root);

// Rollup-specific proof verification
bool verify_rollup_proof(const char* proof, const char* block_hash, const char* prev_hash, const char* tx_root);

#ifdef __cplusplus
}
#endif
