#include "proto_utils.h"
#include "identity.h"
#include "../crypto_utils.h"
#include "../../build/generated/identity.pb.h"

bool serializeIdentity(const ZkIdentity& identity, std::string& out) {
    identity::ZkIdentityProto proto;
    proto.set_uuid(identity.uuid);
    proto.set_name(identity.name);
    proto.set_publickey(identity.publicKey);
    proto.set_metadatahash(identity.metadataHash);
    proto.set_createdat(identity.createdAt);

    if (identity.zkProof)
        proto.set_zkproof(Crypto::toHex(*identity.zkProof));

    if (identity.falconSignature)
        proto.set_falconsignature(Crypto::toHex(identity.falconSignature.value()));

    if (identity.dilithiumSignature)
        proto.set_dilithiumsignature(Crypto::toHex(identity.dilithiumSignature.value()));

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

    identity.zkProof = proto.zkproof().empty() ? std::nullopt
                                               : std::make_optional(Crypto::fromHex(proto.zkproof()));

    if (!proto.falconsignature().empty())
        identity.falconSignature = Crypto::fromHex(proto.falconsignature());

    if (!proto.dilithiumsignature().empty())
        identity.dilithiumSignature = Crypto::fromHex(proto.dilithiumsignature());

    return true;
}
