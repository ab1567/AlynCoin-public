#ifndef ROLLUP_BLOCK_H
#define ROLLUP_BLOCK_H

#include <vector>
#include <string>
#include "../transaction.h"

class RollupBlock {
private:
    int index;
    std::string previousHash;
    std::vector<Transaction> transactions;
    std::string timestamp;
    std::string rollupHash;
    std::string nonce;
    std::vector<std::pair<std::string, double>> compressedDelta; // ✅ New compressed delta
    std::string recursiveProof; // ✅ Recursive proof hash

public:
    RollupBlock();
    RollupBlock(int idx, const std::string& prevHash, const std::vector<Transaction>& txs);

    std::string calculateMerkleRoot() const;
    std::string calculateHash() const;
    std::string rollupProof;
    std::string merkleRoot;
    void generateRollupProof(const std::unordered_map<std::string, double>& stateBefore,
                             const std::unordered_map<std::string, double>& stateAfter,
                             const std::string& prevProof);
    bool verifyRollupProof() const;

    std::string getHash() const;
    std::string getPreviousHash() const;
    int getIndex() const;
    std::vector<std::string> getTransactionHashes() const;
    const std::vector<Transaction>& getTransactions() const;
    std::string getRollupProof() const { return rollupProof; }
    std::string getMerkleRoot() const { return merkleRoot; }
    std::string getNonce() const { return nonce; }
    void setNonce(const std::string& newNonce) { nonce = newNonce; }

    std::string serialize() const;
    static RollupBlock deserialize(const std::string& data);
};

#endif
