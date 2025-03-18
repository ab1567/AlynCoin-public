#ifndef KECCAK_H
#define KECCAK_H

#include <vector>
#include <string>
#include <cstdint>  // ✅ Added this for uint8_t

class Keccak {
public:
    static std::vector<uint8_t> keccak256_raw(const std::vector<uint8_t>& input);
    static std::string keccak256(const std::string& input);
};

#endif // KECCAK_H
