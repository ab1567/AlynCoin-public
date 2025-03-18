// src/blockchain.h

#ifndef BLOCKCHAIN_H
#define BLOCKCHAIN_H

#include "block.h"
#include <vector>

class Blockchain {
public:
    std::vector<Block> chain;

    Blockchain() {
        // Create the genesis block
        addBlock(Block(0, "0", "Genesis Block Data", 0));
    }

    void addBlock(const Block &newBlock);
    void displayBlockchain();
};

#endif
