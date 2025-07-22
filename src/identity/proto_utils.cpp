#include "proto_utils.h"
#include "identity.h"
#include "../crypto_utils.h"
#include <generated/identity.pb.h>

bool serializeIdentity(const ZkIdentity& identity, std::string& out) {
    identity::ZkIdentityProto proto;
    proto.set_uuid(identity.uuid);
    proto.set_name(identity.name);
    proto.set_publickey(identity.publicKey);
    proto.set_metadatahash(identity.metadataHash);
    proto.set_createdat(identity.createdAt);

    if (identity.zkProof && !identity.zkProof->empty()) {
        proto.set_zkproof(reinterpret_cast<const char*>(identity.zkProof->data()), identity.zkProof->size());
    }

    if (identity.falconSignature && !identity.falconSignature->empty()) {
        proto.set_falconsignature(reinterpret_cast<const char*>(identity.falconSignature->data()), identity.falconSignature->size());
    }

    if (identity.dilithiumSignature && !identity.dilithiumSignature->empty()) {
        proto.set_dilithiumsignature(reinterpret_cast<const char*>(identity.dilithiumSignature->data()), identity.dilithiumSignature->size());
    }

    return proto.SerializeToString(&out);
}

bool deserializeIdentity(const std::string& data, ZkIdentity& identity) {
    identity::ZkIdentityProto proto;
    if (!proto.ParseFromString(data)) return false;

    identity.uuid = proto.uuid();
    identity.name = proto.name();
    identity.publicKey = proto.publickey();
    identity.metadataHash = proto.metadatahash();
    identity.createdAt = proto.createdat();

    if (!proto.zkproof().empty()) {
        identity.zkProof = std::vector<unsigned char>(proto.zkproof().begin(), proto.zkproof().end());
    }

    if (!proto.falconsignature().empty()) {
        identity.falconSignature = std::vector<unsigned char>(proto.falconsignature().begin(), proto.falconsignature().end());
    }

    if (!proto.dilithiumsignature().empty()) {
        identity.dilithiumSignature = std::vector<unsigned char>(proto.dilithiumsignature().begin(), proto.dilithiumsignature().end());
    }

    return true;
}
