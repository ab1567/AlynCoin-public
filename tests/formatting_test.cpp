#include "utils/format.h"
#include <cassert>
#include <iostream>

int main() {
    using namespace pretty;
    // shortenHash
    assert(shortenHash("1234567890abcdef1234567890abcdef") == "12345678..90abcdef");
    // timestamp
    assert(formatTimestampISO(0) == std::string("1970-01-01T00:00:00Z"));
    // block format contains fields
    BlockInfo bi{1, 0, "miner", std::string(16,'a'), std::string(16,'b'), 2, 100};
    std::string bline = formatBlock(bi);
    assert(bline.find("height 1") != std::string::npos);
    assert(bline.find("txs 2") != std::string::npos);
    // tx format contains fields
    TxInfo ti{0, "Alice", "Bob", 5.0, estimateFee(5.0), 42, "L1", "confirmed"};
    std::string tline = formatTx(ti);
    assert(tline.find("from Alice") != std::string::npos);
    assert(tline.find("fee") != std::string::npos);
    std::cout << "Formatting tests passed\n";
    return 0;
}
