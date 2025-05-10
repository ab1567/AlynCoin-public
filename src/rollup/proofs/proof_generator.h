#ifndef PROOF_GENERATOR_H
#define PROOF_GENERATOR_H

#include <string>
#include <vector>
#include <unordered_map>
#include "../../transaction.h"

class ProofGenerator {
public:
    static std::string generateAggregatedProof(const std::vector<Transaction>& transactions,
                                               const std::unordered_map<std::string, double>& stateBefore,
                                               const std::unordered_map<std::string, double>& stateAfter,
                                               const std::string& prevBlockHash);

    static std::string generatePublicInput(const std::string& txRoot,
                                           const std::string& stateRootBefore,
                                           const std::string& stateRootAfter);

    static std::string generateRecursiveProof(const std::string& prevProof,
                                              const std::string& newProof);
};

#endif // PROOF_GENERATOR_H
