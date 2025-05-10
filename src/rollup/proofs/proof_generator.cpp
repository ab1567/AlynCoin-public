#include "proof_generator.h"
#include "../circuits/transaction_circuit.h"
#include "../circuits/state_circuit.h"
#include "zk/winterfell_stark.h"
#include "rollup_utils.h"
#include "crypto_utils.h"
#include <thread>
#include <iostream>

std::string ProofGenerator::generatePublicInput(const std::string& txRoot,
                                                const std::string& stateRootBefore,
                                                const std::string& stateRootAfter) {
    return Crypto::hybridHashWithDomain(txRoot + stateRootBefore + stateRootAfter, "PublicInput");
}

std::string ProofGenerator::generateAggregatedProof(const std::vector<Transaction>& transactions,
                                                    const std::unordered_map<std::string, double>& stateBefore,
                                                    const std::unordered_map<std::string, double>& stateAfter,
                                                    const std::string& prevBlockHash) {  // ✅ added arg
    TransactionCircuit txCircuit;
    StateCircuit stBefore, stAfter;

    std::thread txThread([&]() {
        for (const auto& tx : transactions)
            txCircuit.addTransactionData(tx.getSender(), tx.getRecipient(), tx.getAmount(), tx.getTransactionHash());
    });

    std::thread beforeThread([&]() {
        for (const auto& [addr, bal] : stateBefore)
            stBefore.addAccountState(addr, bal);
    });

    std::thread afterThread([&]() {
        for (const auto& [addr, bal] : stateAfter)
            stAfter.addAccountState(addr, bal);
    });

    txThread.join();
    beforeThread.join();
    afterThread.join();

    std::string txRoot = txCircuit.getMerkleRoot();
    std::string stateRootBefore = stBefore.computeStateRootHash();
    std::string stateRootAfter = stAfter.computeStateRootHash();

    std::string seed1 = Crypto::blake3(txRoot + stateRootBefore + stateRootAfter);
    std::string blockHash = Crypto::blake3(seed1);

    RollupUtils::storeRollupMetadata(txRoot, blockHash);  // still needed for consistency
    return RollupStark::generateRollupProof(blockHash, prevBlockHash, txRoot);
}

std::string ProofGenerator::generateRecursiveProof(const std::string& prevProof,
                                                   const std::string& newProof) {
    return Crypto::hybridHashWithDomain(prevProof + newProof, "RecursiveProof");
}
