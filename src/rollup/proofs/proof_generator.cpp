#include "proof_generator.h"
#include "../circuits/transaction_circuit.h"
#include "../circuits/state_circuit.h"
#include "../../zk/winterfell_stark.h"
#include "../rollup/rollup_utils.h"
#include <iostream>
#include <thread>
#include "../../crypto_utils.h"

std::string ProofGenerator::generatePublicInput(const std::string& merkleRoot,
                                                const std::string& stateRootBefore,
                                                const std::string& stateRootAfter) {
    return merkleRoot + stateRootBefore + stateRootAfter;
}

std::string ProofGenerator::generateAggregatedProof(const std::vector<Transaction>& transactions,
                                                    const std::unordered_map<std::string, double>& stateBefore,
                                                    const std::unordered_map<std::string, double>& stateAfter) {
    TransactionCircuit txCircuit;
    StateCircuit stCircuit;

    // Parallel: Add transaction data & state balances
    std::thread txThread([&]() {
        for (const auto& tx : transactions) {
            txCircuit.addTransactionData(tx.getSender(), tx.getRecipient(), tx.getAmount(), tx.getTransactionHash());
        }
    });

    std::thread stateThread([&]() {
        for (const auto& [addr, bal] : stateAfter) {
            stCircuit.addAccountState(addr, bal);
        }
    });

    txThread.join();
    stateThread.join();

    auto txTrace = txCircuit.getTrace();
    auto stTrace = stCircuit.generateStateTrace();
    auto txMerkleRoot = txCircuit.getMerkleRoot();
    auto stMerkleRootBefore = RollupUtils::calculateMerkleRoot({}); // Simplified
    auto stMerkleRootAfter = stCircuit.computeStateRootHash();

    std::string publicInput = generatePublicInput(txMerkleRoot, stMerkleRootBefore, stMerkleRootAfter);

    std::string combinedTrace;
    for (const auto& trace : txTrace) combinedTrace += trace;
    for (const auto& trace : stTrace) combinedTrace += trace;

    std::string blockHash = Crypto::keccak256(combinedTrace);
    std::string zkProof = WinterfellStark::generateProof(blockHash, publicInput, combinedTrace);


    if (zkProof.empty()) {
        std::cerr << "[ERROR] Failed to generate zk-STARK proof!\n";
    }

    return zkProof;
}

std::string ProofGenerator::generateRecursiveProof(const std::string& prevProof,
                                                   const std::string& newProof) {
    return Crypto::hybridHashWithDomain(prevProof + newProof, "RecursiveProof");
}
