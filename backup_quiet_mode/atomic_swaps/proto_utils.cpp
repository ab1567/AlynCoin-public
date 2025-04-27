#include "proto_utils.h"
#include "atomic_swap.pb.h"
#include "../crypto_utils.h"
using namespace atomic;

// ✅ serializeSwap - hex encode optional fields
bool serializeSwap(const AtomicSwap &swap, std::string &out) {
    atomic::AtomicSwapProto proto;
    proto.set_uuid(swap.uuid);
    proto.set_senderaddress(swap.senderAddress);
    proto.set_receiveraddress(swap.receiverAddress);
    proto.set_amount(swap.amount);
    proto.set_secrethash(swap.secretHash);
    if (swap.secret) proto.set_secret(*swap.secret);
    proto.set_createdat(swap.createdAt);
    proto.set_expiresat(swap.expiresAt);
    proto.set_state(static_cast<int>(swap.state));
    if (swap.zkProof) proto.set_zkproof(*swap.zkProof);
    if (swap.falconSignature) proto.set_falconsignature(Crypto::toHex(swap.falconSignature.value()));
    if (swap.dilithiumSignature) proto.set_dilithiumsignature(Crypto::toHex(swap.dilithiumSignature.value()));
    return proto.SerializeToString(&out);
}

// ✅ deserializeSwap - hex decode optional fields
bool deserializeSwap(const std::string &data, AtomicSwap &out) {
    atomic::AtomicSwapProto proto;
    if (!proto.ParseFromString(data)) return false;

    out.uuid = proto.uuid();
    out.senderAddress = proto.senderaddress();
    out.receiverAddress = proto.receiveraddress();
    out.amount = proto.amount();
    out.secretHash = proto.secrethash();
    out.secret = proto.secret().empty() ? std::nullopt : std::make_optional(proto.secret());
    out.createdAt = proto.createdat();
    out.expiresAt = proto.expiresat();
    out.state = static_cast<SwapState>(proto.state());
    out.zkProof = proto.zkproof().empty() ? std::nullopt : std::make_optional(proto.zkproof());

    if (!proto.falconsignature().empty())
        out.falconSignature = Crypto::fromHex(proto.falconsignature());

    if (!proto.dilithiumsignature().empty())
        out.dilithiumSignature = Crypto::fromHex(proto.dilithiumsignature());

    return true;
}
