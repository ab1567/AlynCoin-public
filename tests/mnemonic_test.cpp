#include "../src/mnemonic.h"
#include <cassert>
#include <iostream>

int main(){
    auto words = Mnemonic::generate(12);
    assert(words.size()==12);
    auto entropy = Mnemonic::mnemonicToEntropy(words);
    auto words2 = Mnemonic::entropyToMnemonic(entropy);
    assert(words==words2);
    auto seed = Mnemonic::mnemonicToSeed(words,"test");
    assert(seed.size()==64);
    // invalid word should fail
    auto badWords = words;
    badWords[0] = "zzzz";
    assert(!Mnemonic::validate(badWords));
    // checksum mismatch should fail
    badWords = words;
    std::swap(badWords[0], badWords[1]);
    assert(!Mnemonic::validate(badWords));
    std::cout << "Mnemonic round-trip OK\n";
}
