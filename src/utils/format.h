#pragma once
#include <string>
#include <cstdint>
#include <vector>

namespace pretty {
struct BlockInfo {
    int height;
    uint64_t timestamp;
    std::string miner;
    std::string prevHash;
    std::string hash;
    size_t txCount;
    size_t sizeEstimate;
};

struct TxInfo {
    size_t index;
    std::string from;
    std::string to;
    double amount;
    double fee;
    uint64_t nonce;
    std::string type;
    std::string status;
};

std::string shortenHash(const std::string& h);
std::string formatTimestampISO(uint64_t ts);
std::string formatBlock(const BlockInfo& b);
std::string formatTx(const TxInfo& t);
double estimateFee(double amount);
} // namespace pretty
