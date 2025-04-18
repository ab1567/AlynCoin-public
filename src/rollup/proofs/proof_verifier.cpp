#include "proof_verifier.h"
#include "zk/winterfell_stark.h"
#include "rollup_utils.h"
#include "crypto_utils.h"
#include <iostream>
#include "blockchain.h"
#include "db/db_paths.h"

bool ProofVerifier::verifyProof(const RollupBlock& rollupBlock, const std::string& aggregatedProof) {
    const auto& txHashes = rollupBlock.getTransactionHashes();
    std::string txRoot = RollupUtils::calculateMerkleRoot(txHashes);
    std::string stateRootBefore = rollupBlock.getStateRootBefore();
    std::string stateRootAfter = rollupBlock.getStateRootAfter();

    return verifyRollupProof(aggregatedProof, txHashes, txRoot, stateRootBefore, stateRootAfter);
}

bool ProofVerifier::verifyRollupProof(const std::string& aggregatedProof,
                                      const std::vector<std::string>& txHashes,
                                      const std::string& txRoot,
                                      const std::string& stateRootBefore,
                                      const std::string& stateRootAfter) {
    if (aggregatedProof.empty() || txHashes.empty() || txRoot.empty()
        || stateRootBefore.empty() || stateRootAfter.empty()) {
        std::cerr << "[ERROR] Invalid inputs to verifyRollupProof.\n";
        return false;
    }

    if (!validateProofFormat(aggregatedProof, txHashes.size())) {
        std::cerr << "[ERROR] Invalid proof format or corrupted input.\n";
        return false;
    }

    // ✅ Load consistent txRoot and blockHash from generation time
    auto [storedTxRoot, storedBlockHash] = RollupUtils().loadRollupMetadata();

    Blockchain& chain = Blockchain::getInstance(8333, DBPaths::getBlockchainDB(), false, false);
    std::string prevHash = chain.getLatestBlock().getHash();

    return RollupStark::verifyRollupProof(aggregatedProof, storedBlockHash, prevHash, storedTxRoot);
}

bool ProofVerifier::verifyRecursiveProof(const std::string& prevProof,
                                         const std::string& newProof,
                                         const std::string& combined) {
    std::string recomputed = Crypto::hybridHashWithDomain(prevProof + newProof, "RecursiveProof");
    return recomputed == combined;
}

bool ProofVerifier::validateProofFormat(const std::string& proof, size_t txCount) {
    size_t minLength = 32 + txCount * 8;
    if (proof.length() < minLength) {
        std::cerr << "[ERROR] Proof format invalid. Minimum expected: " << minLength
                  << ", got: " << proof.length() << "\n";
        return false;
    }
    return true;
}
