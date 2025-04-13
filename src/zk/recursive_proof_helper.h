#ifndef RECURSIVE_PROOF_HELPER_H
#define RECURSIVE_PROOF_HELPER_H

#include <string>
#include <vector>

// Now accepts optional custom output path
std::string generateRecursiveProofToFile(
    const std::vector<std::string>& hashes,
    const std::string& address,
    int txCount,
    const std::string& customOutFile = ""
);

#endif // RECURSIVE_PROOF_HELPER_H
