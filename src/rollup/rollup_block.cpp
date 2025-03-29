#include "rollup_block.h"
#include "rollup_utils.h"
#include "proofs/proof_generator.h"
#include "proofs/proof_verifier.h"
#include "../hash.h"
#include "../../crypto_utils.h"
#include <sstream>
#include <json/json.h>
#include <ctime>

RollupBlock::RollupBlock()
    : index(0), previousHash(""), merkleRoot(""), timestamp(""), rollupHash(""), nonce("") {}

RollupBlock::RollupBlock(int idx, const std::string& prevHash, const std::vector<Transaction>& txs)
    : index(idx), previousHash(prevHash), transactions(txs), timestamp(std::to_string(std::time(nullptr))) {

    merkleRoot = calculateMerkleRoot();
    nonce = Crypto::generateRandomHex(16);
    rollupHash = calculateHash();
}

std::string RollupBlock::calculateMerkleRoot() const {
    std::vector<std::string> txHashes;
    for (const auto& tx : transactions) {
        txHashes.push_back(tx.getHash());
    }
    return RollupUtils::calculateMerkleRoot(txHashes);
}

std::string RollupBlock::calculateHash() const {
    std::stringstream ss;
    ss << "[RollupBlock|"
       << index << "|" << previousHash << "|" << merkleRoot << "|" << timestamp << "|" << nonce << "]";
    return Crypto::hybridHash(ss.str());
}

void RollupBlock::generateRollupProof(const std::unordered_map<std::string, double>& stateBefore,
                                      const std::unordered_map<std::string, double>& stateAfter,
                                      const std::string& prevProof) {
    rollupProof = ProofGenerator::generateAggregatedProof(transactions, stateBefore, stateAfter);

    stateRootBefore = RollupUtils::calculateStateRoot(stateBefore);
    stateRootAfter = RollupUtils::calculateStateRoot(stateAfter);

    compressedDelta = RollupUtils::compressStateDelta(stateBefore, stateAfter);
    recursiveProof = ProofGenerator::generateRecursiveProof(prevProof, rollupProof);
}

bool RollupBlock::verifyRollupProof() const {
    std::vector<std::string> txHashes;
    for (const auto& tx : transactions) {
        txHashes.push_back(tx.getHash());
    }

    std::cout << "\n🔎 [DEBUG] Verifying RollupBlock Locally:\n";
    std::cout << " ↪️ Proof Length: " << rollupProof.length() << "\n";
    std::cout << " 🌳 Merkle Root: " << merkleRoot << "\n";
    std::cout << " 🔐 State Root Before: " << stateRootBefore << "\n";
    std::cout << " 🔐 State Root After:  " << stateRootAfter << "\n";
    std::cout << " 🧾 TX Count: " << txHashes.size() << "\n";

    bool mainProofValid = ProofVerifier::verifyRollupProof(
        rollupProof,
        txHashes,
        merkleRoot,
        stateRootBefore,
        stateRootAfter
    );

    bool recursiveValid = ProofVerifier::verifyRecursiveProof(
        previousHash,
        rollupProof,
        recursiveProof
    );

    std::cout << " ✅ Main Proof Valid: " << (mainProofValid ? "Yes" : "No") << "\n";
    std::cout << " 🔁 Recursive Proof Valid: " << (recursiveValid ? "Yes" : "No") << "\n";

    return mainProofValid && recursiveValid;
}

std::vector<std::string> RollupBlock::getTransactionHashes() const {
    std::vector<std::string> hashes;
    for (const auto& tx : transactions) {
        hashes.push_back(tx.getHash());
    }
    return hashes;
}

std::string RollupBlock::getHash() const {
    return rollupHash;
}

std::string RollupBlock::getPreviousHash() const {
    return previousHash;
}

int RollupBlock::getIndex() const {
    return index;
}

const std::vector<Transaction>& RollupBlock::getTransactions() const {
    return transactions;
}

std::string RollupBlock::serialize() const {
    Json::Value root;
    root["index"] = index;
    root["previousHash"] = previousHash;
    root["merkleRoot"] = merkleRoot;
    root["timestamp"] = timestamp;
    root["rollupHash"] = rollupHash;
    root["rollupProof"] = rollupProof;
    root["recursiveProof"] = recursiveProof;
    root["nonce"] = nonce;
    root["stateRootBefore"] = stateRootBefore;
    root["stateRootAfter"] = stateRootAfter;

    Json::Value txArray;
    for (const auto& tx : transactions) {
        txArray.append(tx.toJSON());
    }
    root["transactions"] = txArray;

    Json::Value deltaArray;
    for (const auto& [addr, delta] : compressedDelta) {
        Json::Value d;
        d["address"] = addr;
        d["delta"] = delta;
        deltaArray.append(d);
    }
    root["compressedDelta"] = deltaArray;

    Json::StreamWriterBuilder writer;
    return Json::writeString(writer, root);
}

RollupBlock RollupBlock::deserialize(const std::string& data) {
    Json::Reader reader;
    Json::Value root;
    reader.parse(data, root);

    int idx = root["index"].asInt();
    std::string prevHash = root["previousHash"].asString();

    std::vector<Transaction> txs;
    for (const auto& txJson : root["transactions"]) {
        txs.push_back(Transaction::fromJSON(txJson));
    }

    RollupBlock block(idx, prevHash, txs);
    block.rollupProof = root["rollupProof"].asString();
    block.recursiveProof = root["recursiveProof"].asString();
    block.rollupHash = root["rollupHash"].asString();
    block.nonce = root["nonce"].asString();
    block.stateRootBefore = root["stateRootBefore"].asString();
    block.stateRootAfter = root["stateRootAfter"].asString();

    for (const auto& d : root["compressedDelta"]) {
        std::string addr = d["address"].asString();
        double delta = d["delta"].asDouble();
        block.compressedDelta.emplace_back(addr, delta);
    }

    return block;
}
