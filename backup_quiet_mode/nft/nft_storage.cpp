#include "nft_storage.h"
#include "../db/rocksdb_wrapper.h"
#include <iostream>

namespace NFTStorage {

    std::string makeKey(const std::string& id) {
        return "nft_" + id;
    }

    bool saveNFT(const NFT& nft, rocksdb::DB* db) {
        NFTProto proto = nft.toProto();
        std::string serialized;
        if (!proto.SerializeToString(&serialized)) {
quietPrint( "❌ Failed to serialize NFT!" << std::endl);
            return false;
        }

        rocksdb::Status s = db->Put(rocksdb::WriteOptions(), makeKey(nft.id), serialized);
        return s.ok();
    }

    bool loadNFT(const std::string& id, NFT& nft, rocksdb::DB* db) {
        std::string value;
        rocksdb::Status s = db->Get(rocksdb::ReadOptions(), makeKey(id), &value);
        if (!s.ok()) return false;

        NFTProto proto;
        if (!proto.ParseFromString(value)) return false;

        nft.fromProto(proto);
        return true;
    }

    std::vector<NFT> loadAllNFTs(rocksdb::DB* db) {
        std::vector<NFT> result;
        std::unique_ptr<rocksdb::Iterator> it(db->NewIterator(rocksdb::ReadOptions()));
        for (it->SeekToFirst(); it->Valid(); it->Next()) {
            if (it->key().ToString().rfind("nft_", 0) == 0) {
                NFTProto proto;
                if (proto.ParseFromString(it->value().ToString())) {
                    NFT nft;
                    nft.fromProto(proto);
                    result.push_back(nft);
                }
            }
        }
        return result;
    }
}
