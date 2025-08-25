#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <json/json.h>
#include "crypto_utils.h"

struct L2Tx {
    std::string from;
    std::string to;
    uint64_t nonce{0};
    uint64_t fee{0};
    std::vector<uint8_t> calldata;
    uint64_t gas_limit{0};
    uint64_t chainId{0};
    uint32_t version{0};

    Json::Value toJSON() const {
        Json::Value v;
        v["from"] = from;
        v["to"] = to;
        v["nonce"] = Json::UInt64(nonce);
        v["fee"] = Json::UInt64(fee);
        v["calldata"] = Crypto::toHex(calldata);
        v["gas_limit"] = Json::UInt64(gas_limit);
        v["chainId"] = Json::UInt64(chainId);
        v["version"] = version;
        return v;
    }

    static L2Tx fromJSON(const Json::Value& v) {
        L2Tx tx;
        tx.from = v["from"].asString();
        tx.to = v["to"].asString();
        tx.nonce = v["nonce"].asUInt64();
        tx.fee = v["fee"].asUInt64();
        tx.calldata = Crypto::fromHex(v["calldata"].asString());
        tx.gas_limit = v["gas_limit"].asUInt64();
        tx.chainId = v["chainId"].asUInt64();
        tx.version = v["version"].asUInt();
        return tx;
    }
};
