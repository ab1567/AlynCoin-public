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
    std::string dataToSign = uuid + name + publicKey + metadataHash;
    auto hashBytes = Crypto::sha256ToBytes(dataToSign);

    std::cerr << "[DEBUG] Signing Identity with address: " << signerAddress << "\n";
    std::cerr << "  Message Hash: " << Crypto::toHex(hashBytes) << "\n";

    auto falKeys = Crypto::loadFalconKeys(signerAddress);
    auto dilKeys = Crypto::loadDilithiumKeys(signerAddress);

    std::vector<uint8_t> sigFalcon = Crypto::signWithFalcon(hashBytes, falKeys.privateKey);
    std::vector<uint8_t> sigDilithium = Crypto::signWithDilithium(hashBytes, dilKeys.privateKey);

    falconSignature = Crypto::toHex(sigFalcon);
    dilithiumSignature = Crypto::toHex(sigDilithium);

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

    zkProof = WinterfellStark::generateIdentityProof(uuid, name, metadataHash);
    std::cerr << "[ZK] ✅ Proof generated. Size: " << zkProof->size() << " bytes\n";

    return !zkProof->empty();
}
bool ZkIdentity::verifySignature() const {
    std::string dataToVerify = uuid + name + publicKey + metadataHash;
    std::vector<uint8_t> msgHash = Crypto::sha256ToBytes(dataToVerify);

    std::cerr << "[DEBUG] Verifying Identity Signature...\n";

    std::vector<uint8_t> pubFal = Crypto::getPublicKeyFalcon(uuid);
    std::vector<uint8_t> sigFal = Crypto::fromHex(*falconSignature);

    std::vector<uint8_t> pubDil = Crypto::getPublicKeyDilithium(uuid);
    std::vector<uint8_t> sigDil = Crypto::fromHex(*dilithiumSignature);

    bool validFalcon = Crypto::verifyWithFalcon(msgHash, sigFal, pubFal);
    bool validDilithium = Crypto::verifyWithDilithium(msgHash, sigDil, pubDil);

    std::cerr << "  ✅ Falcon Valid: " << validFalcon << ", Dilithium Valid: " << validDilithium << "\n";

    return validFalcon && validDilithium;
}
