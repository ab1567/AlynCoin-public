#include "blockchain.h"
#include <cassert>
int main() {
    Blockchain &bc = Blockchain::getInstanceNoDB();
    bc.clearChain();

    std::string prev = std::string(GENESIS_PARENT_HASH);
    for(int i=0;i<10;i++) {
        Block blk; blk.setIndex(i); blk.setPreviousHash(prev); blk.setHash(std::string(64,'a'+i)); blk.setDifficulty(1); assert(bc.acceptBlock(blk)); prev = blk.getHash();
    }
    std::string forkPrev = std::string(64,'a'+8); // block at height 8
    Block x1; x1.setIndex(9); x1.setPreviousHash(forkPrev); x1.setHash(std::string(64,'x')); x1.setDifficulty(2); assert(bc.acceptBlock(x1));
    Block x2; x2.setIndex(10); x2.setPreviousHash(std::string(64,'x')); x2.setHash(std::string(64,'y')); x2.setDifficulty(2); assert(bc.acceptBlock(x2));
    Block x3; x3.setIndex(11); x3.setPreviousHash(std::string(64,'y')); x3.setHash(std::string(64,'z')); x3.setDifficulty(2); assert(bc.acceptBlock(x3));

    assert(bc.getLatestBlock().getHash() == std::string(64,'z'));
    assert(bc.getReorgCount() == 1);
    return 0;
}
