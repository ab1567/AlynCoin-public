#include "proto_utils.h"
#include "../../build/generated/identity.pb.h"

bool serializeIdentity(const ZkIdentity& identity, std::string& out) {
    identity::ZkIdentityProto proto;
    proto.set_uuid(identity.uuid);
    proto.set_name(identity.name);
    proto.set_publickey(identity.publicKey);
    proto.set_metadatahash(identity.metadataHash);
    proto.set_createdat(identity.createdAt);
    if (identity.zkProof) proto.set_zkproof(*identity.zkProof);
    if (identity.falconSignature) proto.set_falconsignature(*identity.falconSignature);
    if (identity.dilithiumSignature) proto.set_dilithiumsignature(*identity.dilithiumSignature);
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
    identity.zkProof = proto.zkproof().empty() ? std::nullopt : std::make_optional(proto.zkproof());
    identity.falconSignature = proto.falconsignature().empty() ? std::nullopt : std::make_optional(proto.falconsignature());
    identity.dilithiumSignature = proto.dilithiumsignature().empty() ? std::nullopt : std::make_optional(proto.dilithiumsignature());

    return true;
}
