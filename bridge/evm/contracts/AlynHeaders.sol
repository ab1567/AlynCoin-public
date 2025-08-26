// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title AlynHeaders
 * @notice Lightweight verification of Alyn block headers and transaction inclusion proofs.
 * The implementation is intentionally simplified for demonstration purposes and does not
 * aim to be production ready. Headers are linked by their `parent` hash and each header
 * contributes a `difficulty` amount of work to the chain. The contract stores the
 * cumulative work and exposes a Merkle proof based inclusion check for transactions.
 */
contract AlynHeaders {
    struct Header {
        bytes32 parent;       // hash of previous header
        bytes32 txMerkleRoot; // merkle root of transactions in this block
        uint256 totalDifficulty; // cumulative difficulty up to this block
    }

    // mapping of header hash to the stored header data
    mapping(bytes32 => Header) public headers;
    // latest known header
    bytes32 public tip;

    /**
     * @param genesisHash hash of a trusted genesis/anchor header
     * @param genesisRoot merkle root of the genesis block
     * @param genesisDifficulty difficulty assigned to genesis
     */
    constructor(bytes32 genesisHash, bytes32 genesisRoot, uint256 genesisDifficulty) {
        headers[genesisHash] = Header({
            parent: bytes32(0),
            txMerkleRoot: genesisRoot,
            totalDifficulty: genesisDifficulty
        });
        tip = genesisHash;
    }

    /**
     * @notice Submit a new header extending a known parent.
     * The header hash is computed as keccak256(parent || txRoot || difficulty || nonce).
     * Difficulty validation is drastically simplified: the resulting hash must be less
     * than `type(uint256).max / difficulty`.
     */
    function pushHeader(
        bytes32 parent,
        bytes32 txMerkleRoot,
        uint256 difficulty,
        uint256 nonce
    ) external returns (bytes32 hash) {
        require(headers[parent].txMerkleRoot != bytes32(0), "unknown parent");
        hash = keccak256(abi.encode(parent, txMerkleRoot, difficulty, nonce));
        require(headers[hash].txMerkleRoot == bytes32(0), "exists");
        // very naive proof-of-work check
        require(uint256(hash) < type(uint256).max / difficulty, "insufficient work");

        uint256 cumulative = headers[parent].totalDifficulty + difficulty;
        headers[hash] = Header({parent: parent, txMerkleRoot: txMerkleRoot, totalDifficulty: cumulative});
        tip = hash;
    }

    /**
     * @notice Verify that `txHash` is included in the block identified by `headerHash`.
     * Merkle proofs are expected to be sibling hashes ordered such that the smaller hash
     * is concatenated first. This avoids needing explicit direction bits and is sufficient
     * for this prototype.
     */
    function verifyTxInclusion(
        bytes32 headerHash,
        bytes32[] calldata proof,
        bytes32 txHash
    ) external view returns (bool) {
        Header memory h = headers[headerHash];
        require(h.txMerkleRoot != bytes32(0), "unknown header");
        bytes32 computed = txHash;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 p = proof[i];
            computed = computed < p ? keccak256(abi.encodePacked(computed, p)) : keccak256(abi.encodePacked(p, computed));
        }
        return computed == h.txMerkleRoot;
    }
}
