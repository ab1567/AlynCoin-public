#include "proof_generator.h"
#include "../circuits/transaction_circuit.h"
#include "../circuits/state_circuit.h"
#include "../../zk/winterfell_stark.h"
#include "../rollup/rollup_utils.h"
#include <iostream>
#include <thread>
#include "../../crypto_utils.h"

std::string ProofGenerator::generatePublicInput(const std::string& txRoot,
                                                const std::string& stateRootBefore,
                                                const std::string& stateRootAfter) {
    return Crypto::hybridHashWithDomain(txRoot + stateRootBefore + stateRootAfter, "PublicInput");
}

std::string ProofGenerator::generateAggregatedProof(const std::vector<Transaction>& transactions,
                                                    const std::unordered_map<std::string, double>& stateBefore,
                                                    const std::unordered_map<std::string, double>& stateAfter) {
    TransactionCircuit txCircuit;
    StateCircuit stBefore, stAfter;

    // Parallel processing for better performance
    std::thread txThread([&]() {
        for (const auto& tx : transactions) {
            txCircuit.addTransactionData(tx.getSender(), tx.getRecipient(), tx.getAmount(), tx.getTransactionHash());
        }
    });

    std::thread beforeThread([&]() {
        for (const auto& [addr, bal] : stateBefore) {
            stBefore.addAccountState(addr, bal);
        }
    });

    std::thread afterThread([&]() {
        for (const auto& [addr, bal] : stateAfter) {
            stAfter.addAccountState(addr, bal);
        }
    });

    txThread.join();
    beforeThread.join();
    afterThread.join();

    std::string txMerkleRoot = txCircuit.getMerkleRoot();
    std::string stRootBefore = stBefore.computeStateRootHash();
    std::string stRootAfter = stAfter.computeStateRootHash();

    std::string publicInput = generatePublicInput(txMerkleRoot, stRootBefore, stRootAfter);

    // Trace composition
    std::string combinedTrace;
    for (const auto& hash : txCircuit.getTrace()) {
        combinedTrace += hash;
    }
    for (const auto& hash : stAfter.generateStateTrace()) {
        combinedTrace += hash;
    }

    std::string fullTraceHash = Crypto::keccak256(combinedTrace);

    // ✅ Generate real zk-STARK proof from trace & public input
    std::string zkProof = WinterfellStark::generateProof(fullTraceHash, publicInput, combinedTrace);

    if (zkProof.empty()) {
        std::cerr << "[ERROR] zk-STARK generation failed\n";
    }

    return zkProof;
}

std::string ProofGenerator::generateRecursiveProof(const std::string& prevProof,
                                                   const std::string& newProof) {
    return Crypto::hybridHashWithDomain(prevProof + newProof, "RecursiveProof");
}
