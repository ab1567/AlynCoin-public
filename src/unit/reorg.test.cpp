#include "blockchain.h"
#include <cassert>
int main() {
    Blockchain &bc = Blockchain::getInstanceNoDB();
    bc.clearChain();

    Block g;
    g.setIndex(0);
    g.setPreviousHash(std::string(GENESIS_PARENT_HASH));
    g.setHash(std::string(64, 'a'));
    g.setDifficulty(1);
    assert(bc.acceptBlock(g));

    Block b;
    b.setIndex(1);
    b.setPreviousHash(std::string(64, 'a'));
    b.setHash(std::string(64, 'b'));
    b.setDifficulty(1);
    assert(bc.acceptBlock(b));

    Block c;
    c.setIndex(2);
    c.setPreviousHash(std::string(64, 'b'));
    c.setHash(std::string(64, 'c'));
    c.setDifficulty(1);
    assert(bc.acceptBlock(c));

    Block bp;
    bp.setIndex(1);
    bp.setPreviousHash(std::string(64, 'a'));
    bp.setHash(std::string(64, 'd'));
    bp.setDifficulty(2);
    assert(bc.acceptBlock(bp));

    Block cp;
    cp.setIndex(2);
    cp.setPreviousHash(std::string(64, 'd'));
    cp.setHash(std::string(64, 'e'));
    cp.setDifficulty(2);
    assert(bc.acceptBlock(cp));

    Block dp;
    dp.setIndex(3);
    dp.setPreviousHash(std::string(64, 'e'));
    dp.setHash(std::string(64, 'f'));
    dp.setDifficulty(2);
    assert(bc.acceptBlock(dp));

    assert(bc.getLatestBlock().getHash() == std::string(64, 'f'));
    return 0;
}
