#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace Mnemonic {
std::vector<std::string> generate(int wordCount = 12);
std::vector<uint8_t> mnemonicToEntropy(const std::vector<std::string>& words);
std::vector<std::string> entropyToMnemonic(const std::vector<uint8_t>& entropy);
std::vector<uint8_t> mnemonicToSeed(const std::vector<std::string>& words, const std::string& passphrase = "");
bool validate(const std::vector<std::string>& words);
}
