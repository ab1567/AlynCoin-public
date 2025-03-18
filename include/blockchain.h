#ifndef BLOCKCHAIN_H
#define BLOCKCHAIN_H

#include <vector>
#include "block.h"

class Blockchain {
private:
    std::vector<Block> chain;
public:
    Blockchain();
    void addBlock(Block newBlock);
    Block getLatestBlock() const;
};

#endif
