#include "nft.h"
#include "../src/crypto_utils.h"
#include "../zk/winterfell_stark.h"
#include "../src/blockchain.h"
#include <nlohmann/json.hpp>
#include <iostream>
#include <sstream>
#include <cstdlib>
#include <fstream>
#include <unistd.h>
#include <termios.h>
#include <csignal>
#include <sys/wait.h>
#include <chrono>
#include <atomic>
#include <thread>
#include <future>
#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>
#include "../db/db_instance.h"

using json = nlohmann::json;
// 🔧 Helper: build zk-STARK seed for NFTs
std::string buildZkStarkSeed(const NFT& nft) {
    std::ostringstream oss;
    oss << nft.creator << nft.owner << nft.metadata << nft.imageHash << nft.timestamp;
    return oss.str();
}

// ✅ Signature Verification (Falcon + optional Dilithium)
bool NFT::verifySignature() const {
    std::string message = getSignatureMessage();
    std::vector<uint8_t> msgHash = Crypto::sha256ToBytes(message);

    std::vector<uint8_t> pubKeyFalcon = Crypto::getPublicKeyFalcon(creator);
    std::vector<uint8_t> sigFalcon = signature;

    std::cerr << "\n[DEBUG] Verifying NFT Signature:\n";
    std::cerr << "  Message Hash (hex): " << Crypto::toHex(msgHash) << "\n";
    std::cerr << "  FalconPub.size: " << pubKeyFalcon.size() << ", Sig.size: " << sigFalcon.size() << "\n";

    bool valid = Crypto::verifyWithFalcon(msgHash, sigFalcon, pubKeyFalcon);

    if (!dilithium_signature.empty()) {
        std::vector<uint8_t> pubKeyDil = Crypto::getPublicKeyDilithium(creator);
        std::vector<uint8_t> sigDil = dilithium_signature;
        bool dilValid = Crypto::verifyWithDilithium(msgHash, sigDil, pubKeyDil);
        return valid && dilValid;
    }

    return valid;
}

// ✅ zk-STARK
void NFT::generateZkStarkProof() {
    std::string seed = id + creator + owner + metadata + imageHash + std::to_string(timestamp);
    std::string txRoot = creator + metadata + std::to_string(timestamp);  // consistent seed input
    std::string prevHash = "nft-prev";  // can be static unless versioned
    std::string blockHash = Crypto::blake3(seed);

    std::string proof = WinterfellStark::generateProof(blockHash, prevHash, txRoot);
    zkStarkProof = std::vector<uint8_t>(proof.begin(), proof.end());

    std::cerr << "✅ [ZK] NFT zk-STARK proof generated. Size: " << zkStarkProof.size() << " bytes\n";
}

bool NFT::verifyZkStarkProof() const {
    std::string seed = id + creator + owner + metadata + imageHash + std::to_string(timestamp);
    std::string txRoot = creator + metadata + std::to_string(timestamp);
    std::string prevHash = "nft-prev";
    std::string blockHash = Crypto::blake3(seed);

    std::string proofStr(zkStarkProof.begin(), zkStarkProof.end());
    return WinterfellStark::verifyProof(proofStr, blockHash, prevHash, txRoot);
}

// ✅ Submit L2
bool NFT::submitMetadataHashTransaction() const {
    DB::closeInstance();  // Ensure RocksDB instance is closed before subprocess call

    auto runCommand = [](const std::string& cmd) -> bool {
        std::cout << "[DEBUG] Submitting metadata tx: " << cmd << std::endl;

        FILE* pipe = popen(cmd.c_str(), "r");
        if (!pipe) {
            std::cerr << "❌ Failed to open subprocess.\n";
            return false;
        }

        int fd = fileno(pipe);
        fcntl(fd, F_SETFL, O_NONBLOCK);

        std::string output;
        bool success = false;
        char buffer[512];

        auto start = std::chrono::steady_clock::now();
        const int timeoutSeconds = 5;

        while (true) {
            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(fd, &fds);

            struct timeval tv;
            tv.tv_sec = 1;
            tv.tv_usec = 0;

            int ready = select(fd + 1, &fds, nullptr, nullptr, &tv);
            if (ready > 0 && FD_ISSET(fd, &fds)) {
                ssize_t bytes = read(fd, buffer, sizeof(buffer) - 1);
                if (bytes > 0) {
                    buffer[bytes] = '\0';
                    std::string chunk(buffer);
                    std::cout << "[NFT TX] " << chunk;
                    output += chunk;

                    if (chunk.find("✅ Transaction broadcasted") != std::string::npos ||
                        chunk.find("Transaction added") != std::string::npos ||
                        chunk.find("Transactions successfully saved") != std::string::npos) {
                        success = true;
                        break;
                    }
                }
            }

            auto elapsed = std::chrono::steady_clock::now() - start;
            if (std::chrono::duration_cast<std::chrono::seconds>(elapsed).count() > timeoutSeconds)
                break;
        }

        int exitCode = pclose(pipe);
        std::cerr << "[DEBUG] Metadata TX subprocess exited with code: " << exitCode << "\n";
        return success;
    };

    std::string metadataHash = Crypto::sha256(metadata);
    std::string l1 = "/root/AlynCoin/build/alyncoin-cli sendl1 --nonetwork --nodb \"" + creator +
                     "\" \"metadataSink\" 0.0 \"" + metadataHash + "\"";
    std::string l2 = "/root/AlynCoin/build/alyncoin-cli sendl2 --nonetwork --nodb \"" + creator +
                     "\" \"metadataSink\" 0.0 \"" + metadataHash + "\"";

    if (runCommand(l1)) return true;

    std::cerr << "⚠️ L1 transaction failed or timed out. Trying L2...\n";
    if (runCommand(l2)) return true;

    std::cerr << "❌ Metadata transaction failed.\n";
    return false;
}

// ✅ Export to Protobuf
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
    proto.set_creator_identity(creator_identity);
    proto.set_version(version);
    proto.set_nft_type(nft_type);
    proto.set_proof_hash(proof_hash);
    proto.set_extra_data(extra_data);
    proto.set_encrypted_metadata(encrypted_metadata);
    proto.set_expiry_timestamp(expiry_timestamp);
    proto.set_revoked(revoked);
    proto.set_dilithium_signature(dilithium_signature.data(), dilithium_signature.size());

    for (const auto& a : bundledAssets) proto.add_bundled_assets(a);
    for (const auto& h : transferHistory) proto.add_transferledger(h);
    for (const auto& prev : previous_versions) proto.add_previous_versions(prev);  // ✅ Add this line

    return proto;
}

// ✅ Import from Protobuf
bool NFT::fromProto(const NFTProto& proto) {
    id = proto.id();
    creator = proto.creator();
    owner = proto.owner();
    metadata = proto.metadata();
    imageHash = proto.image_hash();
    timestamp = proto.timestamp();
    signature = std::vector<uint8_t>(proto.signature().begin(), proto.signature().end());
    zkStarkProof = std::vector<uint8_t>(proto.zk_stark_proof().begin(), proto.zk_stark_proof().end());
    creator_identity = proto.creator_identity();
    version = proto.version();
    nft_type = proto.nft_type();
    proof_hash = proto.proof_hash();
    extra_data = proto.extra_data();
    encrypted_metadata = proto.encrypted_metadata();
    expiry_timestamp = proto.expiry_timestamp();
    revoked = proto.revoked();
    dilithium_signature = std::vector<uint8_t>(proto.dilithium_signature().begin(), proto.dilithium_signature().end());

    bundledAssets = {proto.bundled_assets().begin(), proto.bundled_assets().end()};
    transferHistory.assign(proto.transferledger().begin(), proto.transferledger().end());

    previous_versions.clear();
    for (int i = 0; i < proto.previous_versions_size(); ++i)
        previous_versions.push_back(proto.previous_versions(i));

    return true;
}

// ✅ JSON export
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
    j["creator_identity"] = creator_identity;
    j["bundled_assets"] = bundledAssets;
    j["transfer_ledger"] = transferHistory;
    j["version"] = version;
    j["nft_type"] = nft_type;
    j["proof_hash"] = proof_hash;
    j["extra_data"] = extra_data;
    j["encrypted_metadata"] = encrypted_metadata;
    j["expiry_timestamp"] = expiry_timestamp;
    j["revoked"] = revoked;
    j["dilithium_signature"] = Crypto::toHex(dilithium_signature);
    return j.dump(2);
}

// ✅ JSON import
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
    nft.creator_identity = j.value("creator_identity", "");
    nft.version = j.value("version", "");
    nft.nft_type = j.value("nft_type", "");
    nft.proof_hash = j.value("proof_hash", "");
    nft.extra_data = j.value("extra_data", "");
    nft.encrypted_metadata = j.value("encrypted_metadata", "");
    nft.expiry_timestamp = j.value("expiry_timestamp", 0);
    nft.revoked = j.value("revoked", false);
    nft.dilithium_signature = Crypto::fromHex(j.value("dilithium_signature", ""));

    nft.bundledAssets = j.value("bundled_assets", std::vector<std::string>{});
    nft.transferHistory = j.value("transfer_ledger", std::vector<std::string>{});
    return nft;
}

// Updated version of reMintNFT
bool reMintNFT(const std::string& creator,
               const std::string& prevNftId,
               const std::string& newMetadata,
               const std::string& imageHash,
               const std::string& signatureScheme,
               const std::string& previousVersion,
               const std::string& previousZkProof) {
    std::string newVersion = std::to_string(std::stoi(previousVersion) + 1);
    std::string metadataHash = calculateHash(newMetadata + imageHash + creator + newVersion);

    // Generate zk-STARK proof (stubbed or actual)
    std::string newZkProof = generateZkStarkProof(newMetadata, imageHash, creator);

    std::cout << "📄 Re-minting NFT v" << newVersion << " with hash: " << metadataHash << "\n";

    // Submit metadata hash as a Layer-1 (or fallback L2) transaction
    bool submitted = submitMetadataHashTransaction(metadataHash, creator, signatureScheme, true);
    if (!submitted) {
        std::cerr << "❌ Failed to submit transaction.\n";
        return false;
    }

    // Optionally save to .alynft for offline reference
    exportNFTtoFile(prevNftId + "_v" + newVersion + ".alynft", metadataHash, creator, newVersion, newZkProof);
    return true;
}

// ✅ Export to .alynft
bool NFT::exportToFile(const std::string& filename) const {
    std::string fname = filename.empty() ? (id + ".alynft") : filename;
    std::ofstream out(fname);
    if (!out) {
        std::cerr << "❌ Failed to write file: " << fname << "\n";
        return false;
    }
    out << toJSON();
    out.close();
    std::cout << "✅ NFT exported to " << fname << "\n";
    return true;
}
//
// 🔓 Utility: hash helper
std::string calculateHash(const std::string& input) {
    return Crypto::sha256(input);
}

// 🔐 zk-STARK generation wrapper
std::string generateZkStarkProof(const std::string& metadata, const std::string& imageHash, const std::string& creator) {
    int64_t ts = std::time(nullptr);
    std::string seed = creator + creator + creator + metadata + imageHash + std::to_string(ts);
    std::string txRoot = creator + metadata + std::to_string(ts);
    std::string prevHash = "nft-prev";
    std::string blockHash = Crypto::blake3(seed);
    return WinterfellStark::generateProof(blockHash, prevHash, txRoot);
}

// 📤 Metadata hash broadcast (external re-minting version)
bool submitMetadataHashTransaction(const std::string& metadataHash,
                                   const std::string& creator,
                                   const std::string& signatureScheme,
                                   bool isReMint) {
    DB::closeInstance();
    auto runCommand = [](const std::string& cmd) -> bool {
        std::cout << "[DEBUG] Submitting metadata tx: " << cmd << std::endl;
        FILE* pipe = popen(cmd.c_str(), "r");
        if (!pipe) {
            std::cerr << "❌ Failed to open subprocess.\n";
            return false;
        }

        int fd = fileno(pipe);
        fcntl(fd, F_SETFL, O_NONBLOCK);

        std::string output;
        bool success = false;
        char buffer[512];

        auto start = std::chrono::steady_clock::now();
        const int timeoutSeconds = 5;

        while (true) {
            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(fd, &fds);
            struct timeval tv = {1, 0};
            int ready = select(fd + 1, &fds, nullptr, nullptr, &tv);
            if (ready > 0 && FD_ISSET(fd, &fds)) {
                ssize_t bytes = read(fd, buffer, sizeof(buffer) - 1);
                if (bytes > 0) {
                    buffer[bytes] = '\0';
                    std::string chunk(buffer);
                    std::cout << "[NFT TX] " << chunk;
                    output += chunk;

                    if (chunk.find("✅ Transaction broadcasted") != std::string::npos ||
                        chunk.find("Transaction added") != std::string::npos ||
                        chunk.find("Transactions successfully saved") != std::string::npos) {
                        success = true;
                        break;
                    }
                }
            }

            if (std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::steady_clock::now() - start).count() > timeoutSeconds) {
                std::cerr << "⚠️ Output timeout reached.\n";
                break;
            }
        }

        int exitCode = pclose(pipe);
        std::cerr << "[DEBUG] Metadata TX subprocess exited with code: " << exitCode << "\n";
        return success;
    };

    std::string l1 = "/root/AlynCoin/build/alyncoin-cli sendl1 --nonetwork --nodb \"" +
                     creator + "\" \"metadataSink\" 0.0 \"" + metadataHash + "\"";
    std::string l2 = "/root/AlynCoin/build/alyncoin-cli sendl2 --nonetwork --nodb \"" +
                     creator + "\" \"metadataSink\" 0.0 \"" + metadataHash + "\"";

    if (runCommand(l1)) return true;
    std::cerr << "⚠️ L1 transaction failed or timed out. Trying L2...\n";
    if (runCommand(l2)) return true;

    std::cerr << "❌ Metadata transaction failed.\n";
    return false;
}

// 💾 Save a simplified NFT export file (.alynft)
void exportNFTtoFile(const std::string& filename, const std::string& metadataHash,
                     const std::string& creator, const std::string& version,
                     const std::string& zkProof) {
    std::ofstream out(filename);
    if (!out) {
        std::cerr << "❌ Failed to export .alynft file\n";
        return;
    }

    out << "{\n"
        << "  \"creator\": \"" << creator << "\",\n"
        << "  \"version\": \"" << version << "\",\n"
        << "  \"metadata_hash\": \"" << metadataHash << "\",\n"
        << "  \"zk_proof\": \"" << zkProof << "\"\n"
        << "}\n";
    out.close();

    std::cout << "✅ Exported re-mint info to " << filename << "\n";
}

