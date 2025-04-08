#include "winterfell_stark.h"
#include "rust_bindings.h"
#include <cstring>
#include <iostream>
#include <sstream>

// 🔗 Required for linking to Rust-generated libzk_winterfell.a
extern "C" {
    char* generate_proof(const char* seed);
    char* generate_proof_bytes(const char* seed, size_t seed_len);  // ✅ Added declaration
    bool verify_proof(const char* proof, const char* seed, const char* block_hash);
}

// ✅ Block zk-STARK Proof Generation
std::string WinterfellStark::generateProof(const std::string& blockHash, const std::string& prevHash, const std::string& txRoot) {
    // Concatenate input data to form proof seed
    std::string seed = blockHash + prevHash + txRoot;

    std::cout << "[zkSTARK] Generating proof with seed: " << seed << "\n";

    char* proof_cstr = generate_proof_bytes(seed.c_str(), seed.size());
    if (!proof_cstr) {
        std::cerr << "[zkSTARK] ❌ Failed to generate zk-STARK proof.\n";
        return "";
    }

    std::string proof(proof_cstr);
    free(proof_cstr);

    std::cout << "[zkSTARK] ✅ zk-STARK proof generated. Size: " << proof.size() << " bytes\n";
    return proof;
}

// ✅ Block zk-STARK Proof Verification
bool WinterfellStark::verifyProof(const std::string& proof, const std::string& blockHash, const std::string& prevHash, const std::string& txRoot) {
    if (proof.empty() || blockHash.empty() || prevHash.empty() || txRoot.empty()) {
        std::cerr << "[zkSTARK] ❌ Invalid input for block zk-STARK proof verification.\n";
        return false;
    }

    std::string seed = blockHash + prevHash + txRoot;
    bool result = verify_proof(proof.c_str(), seed.c_str(), blockHash.c_str());

    std::cout << "[zkSTARK] 🔍 Block Proof Verification Result: " << (result ? "✅ Passed" : "❌ Failed") << "\n";
    return result;
}

// ✅ Transaction zk-STARK Proof Verification
bool WinterfellStark::verifyTransactionProof(const std::string& zkProof, const std::string& sender, const std::string& recipient, double amount, time_t timestamp) {
    if (zkProof.empty() || sender.empty() || recipient.empty()) {
        std::cerr << "[zkSTARK] ❌ Invalid input for transaction zk-STARK proof verification.\n";
        return false;
    }

    std::ostringstream oss;
    oss << sender << recipient << amount << timestamp;
    std::string seed = oss.str();

    bool result = verify_proof(zkProof.c_str(), seed.c_str(), sender.c_str());

    std::cout << "[zkSTARK] 🔍 Transaction Proof Verification Result: " << (result ? "✅ Passed" : "❌ Failed") << "\n";
    return result;
}

// ✅ Transaction zk-STARK Proof Generation
std::string WinterfellStark::generateTransactionProof(const std::string& sender,
                                                      const std::string& recipient,
                                                      double amount,
                                                      time_t timestamp) {
    std::ostringstream oss;
    oss << sender << recipient << amount << timestamp;
    std::string seed = oss.str();

    std::cout << "[zkSTARK] Generating transaction proof with seed: " << seed << "\n";

    char* proof_cstr = generate_proof_bytes(seed.c_str(), seed.size());
    if (!proof_cstr) {
        std::cerr << "[zkSTARK] ❌ Failed to generate transaction zk-STARK proof.\n";
        return "";
    }

    std::string proof(proof_cstr);
    free(proof_cstr);

    std::cout << "[zkSTARK] ✅ Transaction zk-STARK proof generated. Size: " << proof.size() << " bytes\n";
    return proof;
}

// ✅ Identity zk-STARK Proof Generation (mocked for now)
std::optional<std::string> WinterfellStark::generateIdentityProof(const std::string& uuid,
                                                                   const std::string& name,
                                                                   const std::string& metadataHash) {
    std::string seed = uuid + name + metadataHash;

    std::cout << "[zkSTARK] Generating identity proof with seed: " << seed << "\n";

    char* proof_cstr = generate_proof_bytes(seed.c_str(), seed.size());
    if (!proof_cstr) {
        std::cerr << "[zkSTARK] ❌ Failed to generate identity zk-STARK proof.\n";
        return std::nullopt;
    }

    std::string proof(proof_cstr);
    free(proof_cstr);

    std::cout << "[zkSTARK] ✅ Identity zk-STARK proof generated. Size: " << proof.size() << " bytes\n";
    return proof;
}
