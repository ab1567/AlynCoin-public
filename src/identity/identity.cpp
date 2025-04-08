#include "identity.h"
#include "../crypto_utils.h"
#include "../zk/winterfell_stark.h"
#include <sstream>
#include <ctime>

std::string ZkIdentity::toString() const {
    std::ostringstream oss;
    oss << "[Identity] UUID: " << uuid
        << "\n  Name: " << name
        << "\n  PublicKey: " << publicKey
        << "\n  Metadata Hash: " << metadataHash
        << "\n  Created: " << std::ctime(&createdAt);

    if (zkProof) oss << "  zkProof: " << *zkProof << "\n";
    if (falconSignature) oss << "  Falcon Signature: " << *falconSignature << "\n";
    if (dilithiumSignature) oss << "  Dilithium Signature: " << *dilithiumSignature << "\n";

    return oss.str();
}

bool ZkIdentity::sign(const std::string& signerAddress) {
    auto falKeys = Crypto::loadFalconKeys(signerAddress);
    auto dilKeys = Crypto::loadDilithiumKeys(signerAddress);

    std::string dataToSign = uuid + name + publicKey + metadataHash;
    std::vector<unsigned char> bytes(dataToSign.begin(), dataToSign.end());

    falconSignature = Crypto::toHex(Crypto::signWithFalcon(bytes, falKeys.privateKey));
    dilithiumSignature = Crypto::toHex(Crypto::signWithDilithium(bytes, dilKeys.privateKey));

    return !(falconSignature->empty() || dilithiumSignature->empty());
}

bool ZkIdentity::generateZkProof() {
    zkProof = WinterfellStark::generateIdentityProof(uuid, name, metadataHash);
    return !zkProof->empty();
}
