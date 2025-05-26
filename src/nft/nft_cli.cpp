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
#include "crypto/aes_utils.h"
#include <filesystem>
#include "db/db_paths.h"

namespace fs = std::filesystem;
namespace NFTCLI {

std::string getLoadedWalletAddress() {
    const std::string walletFile = DBPaths::getHomePath() + "/.alyncoin/current_wallet.txt";
    std::ifstream file(walletFile);
    std::string address;

    if (file.is_open()) {
        std::getline(file, address);
        file.close();
    }

    // Remove whitespace and non-visible characters
    address.erase(std::remove_if(address.begin(), address.end(),
        [](unsigned char c) { return std::isspace(c) || !std::isprint(c); }), address.end());

    if (address.empty() || address.length() != 40 || address.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos) {
        std::cerr << "❌ No wallet loaded. Please load a wallet first.\n";
        return "";
    }

    return address;
}

std::string generateNFTID(const std::string& creator, const std::string& imageHash, int64_t timestamp) {
    std::string salt = Crypto::sha256(std::to_string(std::rand()));
    return Crypto::sha256(creator + imageHash + std::to_string(timestamp) + salt);
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
        std::cout << "11. Encrypt Metadata (AES-256)\n";
        std::cout << "12. Decrypt Metadata (AES-256)\n";
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
	if (creator.empty()) {
	    std::cout << "⚠️ No wallet loaded. Please enter wallet address manually: ";
	    std::getline(std::cin, creator);
	    if (creator.empty()) {
	        std::cerr << "❌ Aborting mint. Wallet address required.\n";
	        continue;
	    }
	}
	    std::string owner = creator;
	    int64_t ts = std::time(nullptr);
	    std::string id = generateNFTID(creator, imageHash, ts);

	    NFT nft{id, creator, owner, metadata, imageHash, ts, {}};
	    nft.creator_identity = identity;

	    std::string message = nft.getSignatureMessage();
	    auto msgHash = Crypto::sha256ToBytes(message);
	    if (!fs::exists(DBPaths::getKeyDir() + creator + "_private.pem")) {
	    std::cerr << "❌ Missing private key file for: " << creator << "\n";
	    return;
	}
	auto keypair = Crypto::loadFalconKeys(creator);

	    nft.signature = Crypto::signWithFalcon(msgHash, keypair.privateKey);

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
	    if (current.empty()) {
	    std::cout << "⚠️ No wallet loaded. Please enter your wallet address manually: ";
	    std::getline(std::cin, current);
	    if (current.empty()) {
	        std::cerr << "❌ Aborting. Wallet address required.\n";
	        continue;
	    }
	}
	    if (nft.owner != current || nft.revoked) {
	        std::cerr << "❌ Not the owner or NFT is revoked.\n";
	        continue;
	    }

	    nft.transferHistory.push_back(current);
	    nft.owner = newOwner;
	    nft.timestamp = std::time(nullptr);

	    std::string message = nft.getSignatureMessage();
	    auto msgHash = Crypto::sha256ToBytes(message);
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
    std::string current;

    if (choice == 3) {
        current = getLoadedWalletAddress();
        if (current.empty()) {
            std::cout << "⚠️ No wallet loaded. Please enter your wallet address manually: ";
            std::getline(std::cin, current);
            if (current.empty()) {
                std::cerr << "❌ Wallet address is required to view your NFTs.\n";
                continue;
            }
        }
    }

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

    NFT nft;
    if (!NFTStorage::loadNFT(id, nft, DB::getInstanceNoLock()->getRawDB())) {
        std::cerr << "❌ NFT not found in local DB.\n";
        continue;
    }

    std::string currentUser = getLoadedWalletAddress();
    if (currentUser.empty()) {
        std::cout << "⚠️ No wallet loaded. Please enter your wallet address manually: ";
        std::getline(std::cin, currentUser);
        if (currentUser.empty()) {
            std::cerr << "❌ Aborting. Wallet address required.\n";
            continue;
        }
    }

    if (nft.owner != currentUser || nft.revoked) {
        std::cerr << "❌ You are not the owner of this NFT or it is revoked.\n";
        continue;
    }

    std::cout << "New metadata: ";
    std::getline(std::cin, newMetadata);
    std::cout << "Reason for re-mint: ";
    std::getline(std::cin, reason);

    int newVersion = 1;
    if (!nft.version.empty()) {
        try { newVersion = std::stoi(nft.version) + 1; } catch (...) { newVersion = 1; }
    }

    int64_t ts = std::time(nullptr);
    std::string newId = generateNFTID(currentUser, nft.imageHash, ts);

    NFT updated{newId, currentUser, currentUser, newMetadata, nft.imageHash, ts, {}};
    updated.version = std::to_string(newVersion);
    updated.creator_identity = nft.creator_identity;
    updated.expiry_timestamp = nft.expiry_timestamp;
    updated.previous_versions = nft.previous_versions;
    updated.previous_versions.push_back(nft.id);

    std::string message = updated.getSignatureMessage();
    auto msgHash = Crypto::sha256ToBytes(message);
    auto keys = Crypto::loadFalconKeys(currentUser);
    updated.signature = Crypto::signWithFalcon(msgHash, keys.privateKey);

    updated.generateZkStarkProof();

    std::string rehash = Crypto::sha256(updated.metadata + updated.imageHash + updated.version);
    std::cout << "📄 Re-minting NFT v" << updated.version << " with hash: " << rehash << "\n";

    if (!submitMetadataHashTransaction(rehash, currentUser, "falcon", true)) {
        std::cerr << "❌ Metadata transaction failed.\n";
        continue;
    }

    if (!updated.verifySignature() || !NFTStorage::saveNFT(updated, DB::getInstance()->getRawDB())) {
        std::cerr << "❌ Failed to verify or save updated NFT.\n";
        continue;
    }

    std::cout << "✅ NFT re-minted successfully! New ID: " << newId << "\n";
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

    if (me.empty()) {
        std::cout << "⚠️ No wallet loaded. Please enter your wallet address manually: ";
        std::getline(std::cin, me);
        if (me.empty()) {
            std::cerr << "❌ Wallet address is required to show personal stats.\n";
            continue;
        }
    }

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
    for (auto& [type, count] : typeCount) {
        if (count > max) {
            max = count;
            topType = type;
        }
    }

    std::cout << "\n📊 NFT Stats:\n";
    std::cout << "Total: " << total << "\n";
    std::cout << "Mine: " << mine << "\n";
    std::cout << "zk-STARK: " << zk << "\n";
    std::cout << "Most Common Type: " << topType << "\n";
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

            std::string plaintext;
            std::cout << "Enter metadata to encrypt: ";
            std::getline(std::cin, plaintext);

            std::string password;
            std::cout << "Encryption password: ";
            std::getline(std::cin, password);

            std::string encrypted = AES::encrypt(plaintext, password);
            nft.encrypted_metadata = encrypted;
            NFTStorage::saveNFT(nft, DB::getInstance()->getRawDB());

            std::cout << "✅ Encrypted metadata stored.\n";
        }

        else if (choice == 12) {
            std::string id;
            std::cout << "NFT ID: ";
            std::getline(std::cin, id);
            NFT nft;
            if (!NFTStorage::loadNFT(id, nft, DB::getInstance()->getRawDB())) continue;

            if (nft.encrypted_metadata.empty()) {
                std::cout << "⚠️ No encrypted metadata found for this NFT.\n";
                continue;
            }

            std::string password;
            std::cout << "Decryption password: ";
            std::getline(std::cin, password);

            try {
                std::string decrypted = AES::decrypt(nft.encrypted_metadata, password);
                std::cout << "🔓 Decrypted metadata:\n" << decrypted << "\n";
            } catch (const std::exception& e) {
                std::cerr << "❌ Decryption failed: " << e.what() << "\n";
            }
        }

        else std::cerr << "❌ Invalid option.\n";
    }
}

int handleCommand(int argc, char** argv) {
    if (argc == 1) {
        interactiveMenu();
        return 0;
    }

    std::string cmd = argv[1];

if (cmd == "mint" && argc >= 5) {
    std::string creator = argv[2];
    std::string metadata = argv[3];
    std::string imageHash = argv[4];
    std::string identity = (argc >= 6) ? argv[5] : "";

    std::string privKeyPath = DBPaths::getKeyDir() + creator + "_private.pem";
    if (!fs::exists(privKeyPath)) {
        std::cerr << "❌ Missing private key file for wallet: " << privKeyPath << "\n";
        return 1;
    }

    int64_t ts = std::time(nullptr);
    std::string id = generateNFTID(creator, imageHash, ts);
    std::string dataToSign = id + creator + creator + metadata + imageHash + std::to_string(ts);
    auto msgHash = Crypto::sha256ToBytes(dataToSign);
    if (!fs::exists("/root/.alyncoin/keys/" + creator + "_private.pem")) {
    std::cerr << "❌ Missing private key file for: " << creator << "\n";
    return 1;
	}
	auto keypair = Crypto::loadFalconKeys(creator);

    std::vector<uint8_t> sig = Crypto::signWithFalcon(msgHash, keypair.privateKey);

    NFT nft{id, creator, creator, metadata, imageHash, ts, sig};
    nft.creator_identity = identity;
    nft.generateZkStarkProof();

    if (!nft.submitMetadataHashTransactioncli()) {
        std::cerr << "❌ Metadata transaction failed.\n";
        return 1;
    }

    if (!nft.verifySignature() || !NFTStorage::saveNFT(nft, DB::getInstance()->getRawDB())) {
        std::cerr << "❌ Failed to verify or save NFT.\n";
        return 1;
    }

    std::cout << "✅ NFT minted! ID: " << id << "\n";
    return 0;
}

    if (cmd == "transfer" && argc >= 4) {
        std::string nftID = argv[2];
        std::string newOwner = argv[3];
        NFT nft;
        if (!NFTStorage::loadNFT(nftID, nft, DB::getInstance()->getRawDB())) {
            std::cerr << "❌ NFT not found.\n";
            return 1;
        }

        std::string current = getLoadedWalletAddress();
        if (nft.owner != current || nft.revoked) {
            std::cerr << "❌ Not the owner or NFT is revoked.\n";
            return 1;
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
            return 1;
        }

        std::cout << "✅ NFT transferred.\n";
        return 0;
    }

if (cmd == "remint" && argc >= 5) {
    std::string id = argv[2];
    std::string newMetadata = argv[3];
    std::string reason = argv[4];

    std::string currentUser;
    if (argc >= 6) {
        currentUser = argv[5];  // passed by GUI
    } else {
        currentUser = getLoadedWalletAddress();  // fallback for CLI
    }

    if (currentUser.empty()) {
        std::cerr << "❌ No wallet loaded. Please load a wallet or pass address.\n";
        return 1;
    }

    NFT nft;
    if (!NFTStorage::loadNFT(id, nft, DB::getInstance()->getRawDB())) {
        std::cerr << "❌ NFT not found.\n";
        return 1;
    }

    if (nft.owner != currentUser || nft.revoked) {
        std::cerr << "❌ You are not the owner of this NFT or it is revoked.\n";
        return 1;
    }

    int newVersion = 1;
    if (!nft.version.empty()) {
        try { newVersion = std::stoi(nft.version) + 1; } catch (...) { newVersion = 1; }
    }

    int64_t ts = std::time(nullptr);
    std::string newId = generateNFTID(currentUser, nft.imageHash, ts);
    std::string dataToSign = newId + currentUser + currentUser + newMetadata + nft.imageHash + std::to_string(ts);
    auto msgHash = Crypto::sha256ToBytes(dataToSign);
    auto keys = Crypto::loadFalconKeys(currentUser);
    std::vector<uint8_t> sig = Crypto::signWithFalcon(msgHash, keys.privateKey);

    NFT updated{newId, currentUser, currentUser, newMetadata, nft.imageHash, ts, sig};
    updated.version = std::to_string(newVersion);
    updated.creator_identity = nft.creator_identity;
    updated.expiry_timestamp = nft.expiry_timestamp;
    updated.previous_versions = nft.previous_versions;
    updated.previous_versions.push_back(nft.id);

    updated.generateZkStarkProof();

    std::string rehash = Crypto::sha256(updated.metadata + updated.imageHash + updated.version);
    if (!submitMetadataHashTransactioncli(rehash, currentUser, "falcon", true)) {
        std::cerr << "❌ Metadata transaction failed.\n";
        return 1;
    }

    if (!updated.verifySignature() || !NFTStorage::saveNFT(updated, DB::getInstance()->getRawDB())) {
        std::cerr << "❌ Failed to verify or save updated NFT.\n";
        return 1;
    }

    std::cout << "✅ NFT re-minted successfully! New ID: " << newId << "\n";
    return 0;
}

    if (cmd == "export" && argc >= 3) {
        std::string id = argv[2];
        NFT nft;
        if (!NFTStorage::loadNFT(id, nft, DB::getInstance()->getRawDB())) {
            std::cerr << "❌ Not found.\n";
            return 1;
        }
        nft.exportToFile();
        return 0;
    }

    if (cmd == "encrypt" && argc >= 5) {
        std::string id = argv[2];
        std::string plaintext = argv[3];
        std::string password = argv[4];
        NFT nft;
        if (!NFTStorage::loadNFT(id, nft, DB::getInstance()->getRawDB())) {
            std::cerr << "❌ NFT not found.\n";
            return 1;
        }
        nft.encrypted_metadata = AES::encrypt(plaintext, password);
        NFTStorage::saveNFT(nft, DB::getInstance()->getRawDB());
        std::cout << "✅ Encrypted metadata stored.\n";
        return 0;
    }

    if (cmd == "decrypt" && argc >= 4) {
        std::string id = argv[2];
        std::string password = argv[3];
        NFT nft;
        if (!NFTStorage::loadNFT(id, nft, DB::getInstance()->getRawDB())) {
            std::cerr << "❌ NFT not found.\n";
            return 1;
        }
        if (nft.encrypted_metadata.empty()) {
            std::cout << "⚠️ No encrypted metadata found for this NFT.\n";
            return 0;
        }
        try {
            std::string decrypted = AES::decrypt(nft.encrypted_metadata, password);
            std::cout << "🔓 Decrypted metadata:\n" << decrypted << "\n";
        } catch (const std::exception& e) {
            std::cerr << "❌ Decryption failed: " << e.what() << "\n";
            return 1;
        }
        return 0;
    }

  if (cmd == "stats") {
    auto all = NFTStorage::loadAllNFTs(DB::getInstance()->getRawDB());
    std::string me = getLoadedWalletAddress();

    if (me.empty()) {
        std::cout << "⚠️ No wallet loaded. Please enter your wallet address manually: ";
        std::getline(std::cin, me);
    }

    int total = 0, mine = 0, zk = 0;
    std::map<std::string, int> typeCount;

    for (const auto& nft : all) {
        ++total;
        if (!me.empty() && nft.owner == me) ++mine;
        if (!nft.zkStarkProof.empty()) ++zk;
        if (!nft.nft_type.empty()) typeCount[nft.nft_type]++;
    }

    std::string topType = "N/A";
    int max = 0;
    for (auto& [type, count] : typeCount) {
        if (count > max) {
            max = count;
            topType = type;
        }
    }

    std::cout << "\n📊 NFT Stats:\n";
    std::cout << "Total: " << total << "\n";
    std::cout << "Mine: " << (me.empty() ? "N/A (no wallet provided)" : std::to_string(mine)) << "\n";
    std::cout << "zk-STARK: " << zk << "\n";
    std::cout << "Most Common Type: " << topType << "\n";
    return 0;
 }

   if (cmd == "my") {
    std::string current;
    if (argc >= 3) {
        current = argv[2];
    } else {
        current = getLoadedWalletAddress();
    }

    if (current.empty()) {
        std::cerr << "❌ No wallet loaded. Please ensure current_wallet.txt is set or pass wallet as argument.\n";
        return 1;
    }

    auto all = NFTStorage::loadAllNFTs(DB::getInstance()->getRawDB());
    for (const auto& nft : all) {
        if (nft.owner == current) {
            std::cout << nft.toJSON() << "\n\n";
        }
    }
    return 0;
	}

    if (cmd == "verifyhash" && argc >= 3) {
        std::string filepath = argv[2];
        std::ifstream file(filepath, std::ios::binary);
        if (!file) {
            std::cerr << "❌ File not found: " << filepath << "\n";
            return 1;
        }

        std::ostringstream buffer;
        buffer << file.rdbuf();
        std::string contents = buffer.str();
        std::string fileHash = Crypto::sha256(contents);

        auto all = NFTStorage::loadAllNFTs(DB::getInstance()->getRawDB());
        for (const auto& nft : all) {
            if (nft.imageHash == fileHash) {
                std::cout << "✅ NFT found for file!\n" << nft.toJSON() << "\n";
                return 0;
            }
        }

        std::cout << "❌ No NFT found matching the file hash.\n";
        return 1;
    }

    std::cerr << "❌ Unknown or unsupported command. Use interactive mode.\n";
    return -1;
}
} // namespace NFTCLI
