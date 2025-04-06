#ifndef NFT_STORAGE_H
#define NFT_STORAGE_H

#include <string>
#include <vector>
#include "nft.h"
#include <rocksdb/db.h>

namespace NFTStorage {
    bool saveNFT(const NFT& nft, rocksdb::DB* db);
    bool loadNFT(const std::string& id, NFT& nft, rocksdb::DB* db);
    std::vector<NFT> loadAllNFTs(rocksdb::DB* db);
}

#endif // NFT_STORAGE_H
