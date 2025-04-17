#include "proof_generator.h"
#include "../circuits/transaction_circuit.h"
#include "../circuits/state_circuit.h"
#include "../../zk/winterfell_stark.h"
#include "../rollup_utils.h"
#include "../../crypto_utils.h"
#include <thread>
#include <iostream>

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

    std::string txRoot = txCircuit.getMerkleRoot();
    std::string rootBefore = stBefore.computeStateRootHash();
    std::string rootAfter = stAfter.computeStateRootHash();
    std::string publicInput = generatePublicInput(txRoot, rootBefore, rootAfter);

    std::string traceData;
    for (const auto& h : txCircuit.getTrace()) traceData += h;
    for (const auto& h : stAfter.generateStateTrace()) traceData += h;

    std::string traceHash = Crypto::keccak256(traceData);

    return WinterfellStark::generateProof(traceHash, publicInput, traceData);
}

std::string ProofGenerator::generateRecursiveProof(const std::string& prevProof,
                                                   const std::string& newProof) {
    return Crypto::hybridHashWithDomain(prevProof + newProof, "RecursiveProof");
}
