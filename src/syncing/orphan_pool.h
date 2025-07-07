#pragma once
#include <unordered_map>
#include <vector>
#include "block.h"
class OrphanPool {
    std::unordered_multimap<std::string, Block> byPrevHash;
public:
    void add(Block&& blk) { byPrevHash.emplace(blk.getPreviousHash(), std::move(blk)); }
    std::vector<Block> popChildren(const std::string& parent) {
        std::vector<Block> out;
        auto range = byPrevHash.equal_range(parent);
        for (auto it=range.first; it!=range.second; ++it) out.push_back(std::move(it->second));
        byPrevHash.erase(range.first, range.second);
        return out;
    }
    size_t size() const { return byPrevHash.size(); }
};
