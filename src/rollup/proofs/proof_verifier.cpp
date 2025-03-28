#include "proof_verifier.h"
#include "../../zk/winterfell_stark.h"
#include "../rollup_utils.h"
#include <iostream>
#include "../../crypto_utils.h"  // ✅ Needed for Crypto::hybridHash etc.

bool ProofVerifier::verifyRollupProof(const std::string& aggregatedProof,
                                      const std::vector<std::string>& txHashes,
                                      const std::string& rollupRootHash) {
    if (aggregatedProof.empty() || txHashes.empty() || rollupRootHash.empty()) {
        std::cerr << "[ERROR] Invalid input for rollup proof verification.\n";
        return false;
    }

    if (!validateProofFormat(aggregatedProof, txHashes.size())) {
        std::cerr << "[ERROR] Rollup proof failed length sanity check.\n";
        return false;
    }

    std::string merkleRoot = RollupUtils::calculateMerkleRoot(txHashes);
    std::string stateRootBefore = "DummyStateBefore";  // Placeholder - replace with actual if needed
    std::string stateRootAfter = "DummyStateAfter";    // Placeholder

    std::string publicInput = merkleRoot + stateRootBefore + stateRootAfter;
    std::string blockHash = Crypto::keccak256(publicInput);

    bool result = WinterfellStark::verifyProof(aggregatedProof, blockHash, publicInput, blockHash);

    if (result) {
        std::cout << "[INFO] Rollup zk-STARK proof verified successfully.\n";
    } else {
        std::cerr << "[ERROR] Rollup zk-STARK proof verification failed.\n";
    }
    return result;
}

bool ProofVerifier::validateProofFormat(const std::string& proof, size_t txCount) {
    size_t minLength = 32 + txCount * 8;  // Example logic
    if (proof.empty() || proof.length() < minLength) {
        std::cerr << "[ERROR] Proof format invalid. Expected length >= " << minLength
                  << ", got " << proof.length() << "\n";
        return false;
    }
    return true;
}

bool ProofVerifier::verifyRecursiveProof(const std::string& prevProof,
                                         const std::string& newProof,
                                         const std::string& combined) {
    std::string recomputed = Crypto::hybridHashWithDomain(prevProof + newProof, "RecursiveProof");
    return recomputed == combined;
}
