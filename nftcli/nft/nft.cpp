#include "nft.h"
#include "nft_zk.h"  // ✅ Hook in actual zk-STARK proof logic
#include "../src/crypto_utils.h"
#include "../../src/json.hpp"
#include <iostream>

using json = nlohmann::json;

// ✅ Signature Verification (Falcon)
bool NFT::verifySignature() const {
    std::string dataToVerify = id + creator + owner + metadata + imageHash + std::to_string(timestamp);

    std::vector<unsigned char> pubKey = Crypto::getPublicKeyFalcon(creator);
    if (pubKey.empty()) {
        std::cerr << "❌ [NFT] Could not load Falcon public key for creator: " << creator << "\n";
        return false;
    }

    return Crypto::verifyWithFalcon(Crypto::stringToBytes(dataToVerify), signature, pubKey);
}

// ✅ zk-STARK Proof Verification (Delegated to nft_zk)
bool NFT::verifyZkStarkProof() const {
    return verifyNFTZkProof(*this);
}

// ✅ Serialize to Protobuf
NFTProto NFT::toProto() const {
    NFTProto proto;
    proto.set_id(id);
    proto.set_creator(creator);
    proto.set_owner(owner);
    proto.set_metadata(metadata);
    proto.set_image_hash(imageHash);
    proto.set_timestamp(timestamp);
    proto.set_signature(signature.data(), signature.size());
    proto.set_zk_stark_proof(zkStarkProof.data(), zkStarkProof.size());

    if (!version.empty()) proto.set_version(version);
    if (!nft_type.empty()) proto.set_nft_type(nft_type);
    if (!proof_hash.empty()) proto.set_proof_hash(proof_hash);
    if (!extra_data.empty()) proto.set_extra_data(extra_data);

    return proto;
}

// ✅ Deserialize from Protobuf
bool NFT::fromProto(const NFTProto& proto) {
    id = proto.id();
    creator = proto.creator();
    owner = proto.owner();
    metadata = proto.metadata();
    imageHash = proto.image_hash();
    timestamp = proto.timestamp();
    signature = std::vector<uint8_t>(proto.signature().begin(), proto.signature().end());
    zkStarkProof = std::vector<uint8_t>(proto.zk_stark_proof().begin(), proto.zk_stark_proof().end());

    version = proto.version();
    nft_type = proto.nft_type();
    proof_hash = proto.proof_hash();
    extra_data = proto.extra_data();
    return true;
}

// ✅ Convert to JSON
std::string NFT::toJSON() const {
    json j;
    j["id"] = id;
    j["creator"] = creator;
    j["owner"] = owner;
    j["metadata"] = metadata;
    j["image_hash"] = imageHash;
    j["timestamp"] = timestamp;
    j["signature"] = Crypto::toHex(signature);
    j["zk_stark_proof"] = Crypto::toHex(zkStarkProof);

    if (!version.empty()) j["version"] = version;
    if (!nft_type.empty()) j["nft_type"] = nft_type;
    if (!proof_hash.empty()) j["proof_hash"] = proof_hash;
    if (!extra_data.empty()) j["extra_data"] = extra_data;

    return j.dump(2);
}

// ✅ Load from JSON string
NFT NFT::fromJSON(const std::string& jsonStr) {
    NFT nft;
    auto j = json::parse(jsonStr);

    nft.id = j.value("id", "");
    nft.creator = j.value("creator", "");
    nft.owner = j.value("owner", "");
    nft.metadata = j.value("metadata", "");
    nft.imageHash = j.value("image_hash", "");
    nft.timestamp = j.value("timestamp", 0);
    nft.signature = Crypto::fromHex(j.value("signature", ""));
    nft.zkStarkProof = Crypto::fromHex(j.value("zk_stark_proof", ""));

    nft.version = j.value("version", "");
    nft.nft_type = j.value("nft_type", "");
    nft.proof_hash = j.value("proof_hash", "");
    nft.extra_data = j.value("extra_data", "");

    return nft;
}
