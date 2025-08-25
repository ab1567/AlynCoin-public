#ifndef ROLLUP_BLOCK_H
#define ROLLUP_BLOCK_H

#include <vector>
#include <string>
#include "../transaction.h"
#include "../layer2/l2_tx.h"

class RollupBlock {
private:
    int index;
    std::string previousHash;
    std::vector<Transaction> transactions;
    std::string timestamp;
    std::string rollupHash;
    std::string nonce;
    std::string prevL2Root;   // previous L2 state root
    std::string postL2Root;   // post-execution L2 state root
    std::vector<L2Tx> l2Batch;    // raw L2 transactions
    std::string l2ReceiptsCommitment;

    std::vector<std::pair<std::string, double>> compressedDelta;
    std::string recursiveProof;

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
    const std::vector<std::pair<std::string, double>>& getCompressedDelta() const {
	    return compressedDelta;
	}

    std::string getHash() const;
    std::string getPreviousHash() const;
    int getIndex() const;
    const std::vector<Transaction>& getTransactions() const;
    std::vector<std::string> getTransactionHashes() const;
    std::string getTimestamp() const { return timestamp; }
    std::string getRollupProof() const { return rollupProof; }
    std::string getMerkleRoot() const { return merkleRoot; }
    std::string getNonce() const { return nonce; }

    // Legacy getters kept for backward compatibility
    std::string getStateRootBefore() const { return prevL2Root; }
    std::string getStateRootAfter() const { return postL2Root; }

    // New getters
    const std::vector<L2Tx>& getL2Batch() const { return l2Batch; }
    std::string getPrevL2Root() const { return prevL2Root; }
    std::string getPostL2Root() const { return postL2Root; }
    std::string getL2ReceiptsCommitment() const { return l2ReceiptsCommitment; }

    // Setters for new fields
    void setL2Batch(const std::vector<L2Tx>& batch) { l2Batch = batch; }
    void setPrevL2Root(const std::string& r) { prevL2Root = r; }
    void setPostL2Root(const std::string& r) { postL2Root = r; }
    void setL2ReceiptsCommitment(const std::string& c) { l2ReceiptsCommitment = c; }

    void setNonce(const std::string& newNonce) { nonce = newNonce; }

    std::string serialize() const;
    static RollupBlock deserialize(const std::string& data);
};

#endif
