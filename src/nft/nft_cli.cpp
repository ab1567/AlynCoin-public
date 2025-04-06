#include "nft_cli.h"
#include "../nft/nft.h"
#include "../nft/nft_storage.h"
#include "../src/crypto_utils.h"
#include "../db/db_instance.h"
#include <fstream>
#include <iostream>
#include <ctime>
#include <string>
#include <map>
#include <regex>

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

void interactiveMenu() {
    while (true) {
        std::cout << "\n=== Quantum-Resistant NFT CLI ===\n";
        std::cout << "1. Mint NFT\n";
        std::cout << "2. Transfer NFT\n";
        std::cout << "3. View My NFTs\n";
        std::cout << "4. View All NFTs\n";
       std::cout << "5. Re-Mint NFT (Update Metadata) [Advanced]\n";
        std::cout << "6. Export NFT to .alynft File\n";
        std::cout << "7. Show NFT Stats\n";
        std::cout << "8. Exit\n";
        std::cout << "9. Add Bundled Asset\n";
        std::cout << "10. Set Expiry / Revoke NFT\n";
        std::cout << "11. Encrypt Metadata (placeholder)\n";
        std::cout << "Select option: ";

        int choice;
        std::cin >> choice;
        std::cin.ignore();

        if (choice == 1) {
            std::string metadata, imageHash, identity;
            std::cout << "Enter metadata: ";
            std::getline(std::cin, metadata);
            std::cout << "Enter image hash: ";
            std::getline(std::cin, imageHash);
            std::cout << "Optional creator identity tag: ";
            std::getline(std::cin, identity);

            std::string creator = getLoadedWalletAddress();
            std::string owner = creator;
            int64_t ts = std::time(nullptr);
            std::string id = generateNFTID(creator, imageHash, ts);

            std::string dataToSign = id + creator + owner + metadata + imageHash + std::to_string(ts);
            auto msgHash = Crypto::sha256ToBytes(dataToSign);
            auto keypair = Crypto::loadFalconKeys(creator);
            std::vector<uint8_t> sig = Crypto::signWithFalcon(msgHash, keypair.privateKey);

            NFT nft{id, creator, owner, metadata, imageHash, ts, sig};
            nft.creator_identity = identity;
            nft.generateZkStarkProof();

            if (!nft.submitMetadataHashTransaction()) {
                std::cerr << "❌ Metadata transaction failed.\n";
                continue;
            }

            std::cout << "Set expiry timestamp? (0 = no expiry): ";
            std::cin >> nft.expiry_timestamp;
            std::cin.ignore();

            if (!nft.verifySignature() || !NFTStorage::saveNFT(nft, DB::getInstance()->getRawDB())) {
                std::cerr << "❌ Failed to verify or save NFT.\n";
                continue;
            }

            std::cout << "✅ NFT minted! ID: " << id << "\n";
        }

        else if (choice == 2) {
            std::string nftID, newOwner;
            std::cout << "Enter NFT ID: ";
            std::getline(std::cin, nftID);
            std::cout << "Enter new owner address: ";
            std::getline(std::cin, newOwner);

            NFT nft;
            if (!NFTStorage::loadNFT(nftID, nft, DB::getInstance()->getRawDB())) {
                std::cerr << "❌ NFT not found.\n";
                continue;
            }

            std::string current = getLoadedWalletAddress();
            if (nft.owner != current || nft.revoked) {
                std::cerr << "❌ Not the owner or NFT is revoked.\n";
                continue;
            }

            nft.transferHistory.push_back(current);
            nft.owner = newOwner;
            nft.timestamp = std::time(nullptr);

            std::string dataToSign = nft.id + nft.creator + nft.owner + nft.metadata + nft.imageHash + std::to_string(nft.timestamp);
            auto msgHash = Crypto::sha256ToBytes(dataToSign);
            auto keypair = Crypto::loadFalconKeys(current);
            nft.signature = Crypto::signWithFalcon(msgHash, keypair.privateKey);

            if (!nft.verifySignature() || !NFTStorage::saveNFT(nft, DB::getInstance()->getRawDB())) {
                std::cerr << "❌ Failed to verify or save transfer.\n";
                continue;
            }

            std::cout << "✅ NFT transferred.\n";
        }

        else if (choice == 3 || choice == 4) {
            auto allNFTs = NFTStorage::loadAllNFTs(DB::getInstance()->getRawDB());
            std::string current = getLoadedWalletAddress();
            std::cout << (choice == 3 ? "\n🎨 Your NFTs:\n" : "\n🎨 All NFTs:\n");
            for (const auto& nft : allNFTs) {
                if (choice == 4 || nft.owner == current)
                    std::cout << nft.toJSON() << "\n\n";
            }
        }

        else if (choice == 5) {
           std::cout << "⚠️  Re-minting is an advanced feature used for updating NFT metadata with version tracking.\n";
           std::string confirm;
           std::cout << "Do you want to proceed? (y/n): ";
           std::getline(std::cin, confirm);
           if (confirm != "y" && confirm != "Y") {
           std::cout << "❌ Re-minting canceled.\n";
           continue;
       }

         std::string id, newMetadata, reason;
         std::cout << "Enter NFT ID: ";
         std::getline(std::cin, id);

         // Use subprocess to get NFT details (instead of DB)
        std::string nftDataCmd = "./nftcli --getnft " + id;
        FILE* pipe = popen(nftDataCmd.c_str(), "r");
         if (!pipe) {
                std::cerr << "❌ Failed to query NFT info.\n";
                continue;
        }

            char buffer[512];
        std::string result;
        while (fgets(buffer, sizeof(buffer), pipe)) {
                result += buffer;
        }
            pclose(pipe);

            // Parse fields from output (owner, metadata, image hash, version)
        std::string owner, prevMetadata, imageHash, version;
         std::regex ownerR("Owner:\\s*(.+)");
          std::regex metaR("Metadata:\\s*(.+)");
         std::regex hashR("ImageHash:\\s*(.+)");
        std::regex verR("Version:\\s*(\\d+)");

        std::smatch m;
        if (std::regex_search(result, m, ownerR)) owner = m[1];
        if (std::regex_search(result, m, metaR)) prevMetadata = m[1];
        if (std::regex_search(result, m, hashR)) imageHash = m[1];
        if (std::regex_search(result, m, verR)) version = m[1];

            if (owner.empty() || owner != getLoadedWalletAddress()) {
                std::cerr << "❌ You are not the owner of this NFT.\n";
                continue;
        }

            if (prevMetadata.empty() || imageHash.empty() || version.empty()) {
                std::cerr << "❌ Failed to parse existing NFT data.\n";
                continue;
        }

            std::cout << "New metadata: ";
        std::getline(std::cin, newMetadata);
        std::cout << "Reason for re-mint: ";
        std::getline(std::cin, reason);

            std::string scheme;
            std::cout << "Signature scheme (falcon/dilithium): ";
            std::getline(std::cin, scheme);

            bool success = reMintNFT(
                owner, id, newMetadata, imageHash, scheme, version, ""
        );

            if (success) {
                std::cout << "✅ Re-mint submitted successfully.\n";
        } else {
                std::cerr << "❌ Re-mint failed.\n";
        }
        }

        else if (choice == 6) {
            std::string id;
            std::cout << "NFT ID to export: ";
            std::getline(std::cin, id);
            NFT nft;
            if (!NFTStorage::loadNFT(id, nft, DB::getInstance()->getRawDB())) {
                std::cerr << "❌ Not found.\n";
                continue;
            }
            nft.exportToFile();
        }

        else if (choice == 7) {
            auto all = NFTStorage::loadAllNFTs(DB::getInstance()->getRawDB());
            std::string me = getLoadedWalletAddress();
            int total = 0, mine = 0, zk = 0;
            std::map<std::string, int> typeCount;

            for (const auto& nft : all) {
                ++total;
                if (nft.owner == me) ++mine;
                if (!nft.zkStarkProof.empty()) ++zk;
                if (!nft.nft_type.empty()) typeCount[nft.nft_type]++;
            }

            std::string topType = "N/A";
            int max = 0;
            for (auto& [type, count] : typeCount)
                if (count > max) { max = count; topType = type; }

            std::cout << "\n📊 NFT Stats:\nTotal: " << total << "\nMine: " << mine << "\nzk-STARK: " << zk << "\nMost Common Type: " << topType << "\n";
        }

        else if (choice == 8) {
            std::cout << "Exiting NFT CLI...\n";
            break;
        }

        else if (choice == 9) {
            std::string id, asset;
            std::cout << "NFT ID: ";
            std::getline(std::cin, id);
            NFT nft;
            if (!NFTStorage::loadNFT(id, nft, DB::getInstance()->getRawDB())) continue;
            std::cout << "Enter asset (tx ID / data): ";
            std::getline(std::cin, asset);
            nft.bundledAssets.push_back(asset);
            NFTStorage::saveNFT(nft, DB::getInstance()->getRawDB());
            std::cout << "✅ Asset bundled.\n";
        }

        else if (choice == 10) {
            std::string id;
            std::cout << "NFT ID: ";
            std::getline(std::cin, id);
            NFT nft;
            if (!NFTStorage::loadNFT(id, nft, DB::getInstance()->getRawDB())) continue;

            std::cout << "1 = Set Expiry, 2 = Revoke\nOption: ";
            int opt;
            std::cin >> opt;
            std::cin.ignore();
            if (opt == 1) {
                std::cout << "Enter expiry timestamp: ";
                std::cin >> nft.expiry_timestamp;
                std::cin.ignore();
                std::cout << "✅ Expiry set.\n";
            } else {
                nft.revoked = true;
                std::cout << "✅ NFT revoked.\n";
            }
            NFTStorage::saveNFT(nft, DB::getInstance()->getRawDB());
        }

        else if (choice == 11) {
            std::string id;
            std::cout << "NFT ID: ";
            std::getline(std::cin, id);
            NFT nft;
            if (!NFTStorage::loadNFT(id, nft, DB::getInstance()->getRawDB())) continue;
            std::string encrypted;
            std::cout << "Simulated encrypted metadata: ";
            std::getline(std::cin, encrypted);
            nft.encrypted_metadata = encrypted;
            NFTStorage::saveNFT(nft, DB::getInstance()->getRawDB());
            std::cout << "✅ Encrypted metadata added.\n";
        }

        else std::cerr << "❌ Invalid option.\n";
    }
}

int handleCommand(int argc, char** argv) {
    if (argc == 1) {
        interactiveMenu();
        return 0;
    }

    std::cerr << "❌ Unknown or unsupported command. Use interactive mode.\n";
    return -1;
}

} // namespace NFTCLI
