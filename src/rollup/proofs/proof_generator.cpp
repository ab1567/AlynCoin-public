#include "proof_generator.h"
#include "../circuits/transaction_circuit.h"
#include "../circuits/state_circuit.h"
#include "zk/winterfell_stark.h"
#include "rollup_utils.h"
#include "crypto_utils.h"
#include "blockchain.h"
#include <thread>
#include <iostream>
#include "db/db_paths.h"

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

    Blockchain& chain = Blockchain::getInstance(8333, DBPaths::getBlockchainDB(), false, false);
    std::string prevHash = chain.getLatestBlock().getHash();

    std::string seed1 = Crypto::blake3(txRoot + stateRootBefore + stateRootAfter);
    std::string blockHash = Crypto::blake3(seed1);

    RollupUtils::storeRollupMetadata(txRoot, blockHash);
    return RollupStark::generateRollupProof(blockHash, prevHash, txRoot);
}

std::string ProofGenerator::generateRecursiveProof(const std::string& prevProof,
                                                   const std::string& newProof) {
    return Crypto::hybridHashWithDomain(prevProof + newProof, "RecursiveProof");
}
