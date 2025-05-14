#include "identity.h"
#include "../crypto_utils.h"
#include "../zk/winterfell_stark.h"
#include <sstream>
#include <ctime>
#include <iostream>

std::string ZkIdentity::toString() const {
    std::ostringstream oss;
    oss << "[Identity] UUID: " << uuid
        << "\n  Name: " << name
        << "\n  PublicKey: " << publicKey
        << "\n  Metadata Hash: " << metadataHash
        << "\n  Created: " << std::ctime(&createdAt);

    if (zkProof) oss << "  zkProof: " << Crypto::toHex(*zkProof) << "\n";
    if (falconSignature) oss << "  Falcon Signature: " << Crypto::toHex(*falconSignature) << "\n";
    if (dilithiumSignature) oss << "  Dilithium Signature: " << Crypto::toHex(*dilithiumSignature) << "\n";

    return oss.str();
}

bool ZkIdentity::sign(const std::string& signerAddress) {
    std::string dataToSign = uuid + name + publicKey + metadataHash;
    auto hashBytes = Crypto::sha256ToBytes(dataToSign);

    std::cerr << "[DEBUG] Signing Identity with address: " << signerAddress << "\n";
    std::cerr << "  Message Hash: " << Crypto::toHex(hashBytes) << "\n";

    auto falKeys = Crypto::loadFalconKeys(signerAddress);
    auto dilKeys = Crypto::loadDilithiumKeys(signerAddress);

    std::vector<uint8_t> sigFalcon = Crypto::signWithFalcon(hashBytes, falKeys.privateKey);
    std::vector<uint8_t> sigDilithium = Crypto::signWithDilithium(hashBytes, dilKeys.privateKey);

    falconSignature = sigFalcon;
    dilithiumSignature = sigDilithium;

    std::cerr << "[DEBUG] Falcon Signature Length: " << sigFalcon.size() << "\n";
    std::cerr << "[DEBUG] Dilithium Signature Length: " << sigDilithium.size() << "\n";

    return !(falconSignature->empty() || dilithiumSignature->empty());
}

bool ZkIdentity::generateZkProof() {
    std::string seed = uuid + name + metadataHash;

    std::cerr << "[ZK] Generating zk-STARK Identity Proof\n";
    std::cerr << "  - Seed Input: " << seed << "\n";
    std::string seedHash = Crypto::blake3(seed);
    std::cerr << "  - BLAKE3(seed): " << seedHash << "\n";

    std::optional<std::string> proofStrOpt = WinterfellStark::generateIdentityProof(uuid, name, metadataHash);
    if (!proofStrOpt.has_value()) {
        std::cerr << "[ZK] ❌ Proof generation failed (null optional).\n";
        return false;
    }

    zkProof = Crypto::fromHex(*proofStrOpt);
    std::cerr << "[ZK] ✅ Proof generated. Size: " << zkProof->size() << " bytes\n";

    return !zkProof->empty();
}

bool ZkIdentity::verifySignature() const {
    std::string dataToVerify = uuid + name + publicKey + metadataHash;
    std::vector<uint8_t> msgHash = Crypto::sha256ToBytes(dataToVerify);

    std::cerr << "[DEBUG] Verifying Identity Signature...\n";

    std::vector<uint8_t> sigFal = *falconSignature;
    std::vector<uint8_t> sigDil = *dilithiumSignature;

    // Public key is stored as binary string → convert to vector<uint8_t>
    std::vector<uint8_t> pubKey(publicKey.begin(), publicKey.end());

    bool validFalcon = Crypto::verifyWithFalcon(msgHash, sigFal, pubKey);
    bool validDilithium = Crypto::verifyWithDilithium(msgHash, sigDil, pubKey);

    std::cerr << "  ✅ Falcon Valid: " << validFalcon << ", Dilithium Valid: " << validDilithium << "\n";

    return validFalcon && validDilithium;
}
