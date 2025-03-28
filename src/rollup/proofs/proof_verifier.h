#ifndef PROOF_VERIFIER_H
#define PROOF_VERIFIER_H

#include <string>
#include <vector>
#include "../rollup_block.h"

class ProofVerifier {
public:
    static bool verifyProof(const RollupBlock& rollupBlock, const std::string& aggregatedProof);
    static bool verifyRollupProof(const std::string& aggregatedProof,
                                  const std::vector<std::string>& txHashes,
                                  const std::string& rollupRootHash);

    // ✅ Recursive verifier
    static bool verifyRecursiveProof(const std::string& prevProof, const std::string& newProof, const std::string& combined);

private:
    static bool validateProofFormat(const std::string& proof, size_t txCount);
};

#endif // PROOF_VERIFIER_H
