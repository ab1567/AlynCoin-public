#include "nft_cli.h"
#include "../nft/nft.h"
#include "../nft/nft_storage.h"
#include "../src/crypto_utils.h"
#include "../db/db_instance.h"
#include <fstream>
#include <iostream>
#include <ctime>

namespace NFTCLI {

std::string getLoadedWalletAddress() {
    std::ifstream file("/root/.alyncoin/current_wallet.txt");
    std::string address;
    std::getline(file, address);
    return address;
}

std::string generateNFTID(const std::string& creator, const std::string& imageHash, int64_t timestamp) {
    return Crypto::sha256(creator + imageHash + std::to_string(timestamp));
}

int handleCommand(int argc, char** argv) {
    if (argc < 2) return -1;
    std::string cmd = argv[1];

    // ========================
    // 🔹 MINT NFT
    // ========================
    if (cmd == "mintnft" && argc == 4) {
        std::string metadata = argv[2];
        std::string imageHash = argv[3];

        std::string creator = getLoadedWalletAddress();
        int64_t ts = std::time(nullptr);
        std::string id = generateNFTID(creator, imageHash, ts);

        std::string dataToSign = id + creator + creator + metadata + imageHash + std::to_string(ts);
        std::vector<unsigned char> msgHash = Crypto::stringToBytes(Crypto::sha256(dataToSign));

        auto keypair = Crypto::loadFalconKeys(creator);
        if (keypair.privateKey.empty()) {
            std::cerr << "❌ [ERROR] Private key not found for: " << creator << "\n";
            return 1;
        }

        std::vector<unsigned char> signature = Crypto::signWithFalcon(msgHash, keypair.privateKey);
        if (signature.empty()) {
            std::cerr << "❌ [ERROR] Failed to sign NFT data.\n";
            return 1;
        }

        NFT nft{id, creator, creator, metadata, imageHash, ts, signature};

        if (!nft.verifySignature()) {
            std::cerr << "❌ Signature verification failed after signing.\n";
            return 1;
        }

        if (!NFTStorage::saveNFT(nft, DB::getInstance()->getRawDB())) {
            std::cerr << "❌ Failed to save NFT.\n";
            return 1;
        }

        std::cout << "✅ NFT minted! ID: " << id << "\n";
        return 0;
    }

    // ========================
    // 🔹 TRANSFER NFT
    // ========================
    if (cmd == "transfernft" && argc == 4) {
        std::string nftID = argv[2];
        std::string newOwner = argv[3];

        NFT nft;
        if (!NFTStorage::loadNFT(nftID, nft, DB::getInstance()->getRawDB())) {
            std::cerr << "❌ NFT not found.\n";
            return 1;
        }

        std::string current = getLoadedWalletAddress();
        if (nft.owner != current) {
            std::cerr << "❌ You are not the current owner.\n";
            return 1;
        }

        nft.owner = newOwner;
        nft.timestamp = std::time(nullptr);

        std::string dataToSign = nft.id + nft.creator + newOwner + nft.metadata + nft.imageHash + std::to_string(nft.timestamp);
        std::vector<unsigned char> msgHash = Crypto::stringToBytes(Crypto::sha256(dataToSign));
        auto keypair = Crypto::loadFalconKeys(current);
        nft.signature = Crypto::signWithFalcon(msgHash, keypair.privateKey);

        if (!nft.verifySignature()) {
            std::cerr << "❌ Signature invalid after transfer.\n";
            return 1;
        }

        if (!NFTStorage::saveNFT(nft, DB::getInstance()->getRawDB())) {
            std::cerr << "❌ Failed to update NFT.\n";
            return 1;
        }

        std::cout << "✅ NFT transferred to: " << newOwner << "\n";
        return 0;
    }

    // ========================
    // 🔹 VIEW NFTs
    // ========================
    if (cmd == "viewnfts") {
        std::string filter = (argc >= 3) ? argv[2] : "";
        auto allNFTs = NFTStorage::loadAllNFTs(DB::getInstance()->getRawDB());

        std::cout << "\n🎨 NFTs:\n";
        for (const auto& nft : allNFTs) {
            if (filter.empty() || nft.owner == filter) {
                std::cout << nft.toJSON() << "\n\n";
            }
        }
        return 0;
    }

    return -1; // Not an NFT command
}

} // namespace NFTCLI
