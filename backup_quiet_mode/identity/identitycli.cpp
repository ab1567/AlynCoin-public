#include "identity_store.h"
#include "../crypto_utils.h"
#include "proto_utils.h"
#include <iostream>
#include <memory>
#include <string>
#include <map>
#include <limits>
#include "../zk/winterfell_stark.h"

bool verifyIdentity(const ZkIdentity& id) {
    std::string data = id.uuid + id.name + id.publicKey + id.metadataHash;
    std::vector<uint8_t> msgHash = Crypto::sha256ToBytes(data);

    std::cerr << "\n[VERIFY] Identity Verification for UUID: " << id.uuid << "\n";
    std::cerr << "  Hash Input: " << Crypto::toHex(msgHash) << "\n";

    bool falValid = false, dilValid = false, zkValid = false;

    if (id.falconSignature) {
        auto pubFal = Crypto::getPublicKeyFalcon(id.uuid);
        auto sigFal = id.falconSignature.value();
        falValid = Crypto::verifyWithFalcon(msgHash, sigFal, pubFal);
quietPrint( (falValid ? "✅ Falcon signature verified.\n" : "❌ Falcon signature FAILED.\n"));
    }

    if (id.dilithiumSignature) {
        auto pubDil = Crypto::getPublicKeyDilithium(id.uuid);
        auto sigDil = id.dilithiumSignature.value();
        dilValid = Crypto::verifyWithDilithium(msgHash, sigDil, pubDil);
quietPrint( (dilValid ? "✅ Dilithium signature verified.\n" : "❌ Dilithium signature FAILED.\n"));
    }

    if (id.zkProof) {
        zkValid = WinterfellStark::verifyIdentityProof(Crypto::toHex(id.zkProof.value()), id.uuid, id.name, id.metadataHash);
quietPrint( (zkValid ? "✅ zk-STARK identity proof verified.\n" : "❌ zk-STARK proof FAILED.\n"));
    }

    return falValid && dilValid && zkValid;
}


void printMenu() {
    std::cout << "\n[ zk-Identity CLI Menu ]\n"
              << "1. Create Identity\n"
              << "2. View Identity\n"
              << "3. List All Identities\n"
              << "4. Delete Identity\n"
              << "5. Verify Identity\n"
              << "6. Exit\n"
              << "Choose an option: ";
}

int main(int argc, char* argv[]) {
    std::unique_ptr<IdentityStore> store = std::make_unique<IdentityStore>("identitydb");

    // 🚀 Direct command mode (GUI & scripts)
    if (argc >= 2) {
        std::string command = argv[1];

        if (command == "create" && argc == 4) {
            std::string address = argv[2];
            std::string displayName = argv[3];

            ZkIdentity id;
            id.uuid = address;
            id.name = displayName;
            id.publicKey = Crypto::getPublicKey(address);
            id.metadataHash = Crypto::hybridHash(displayName);
            id.createdAt = std::time(nullptr);
            id.generateZkProof();
            id.sign(address);

            if (store->save(id)) {
                std::cout << "✅ Identity created and saved.\n";
                return 0;
            } else {
quietPrint( "❌ Failed to save identity.\n");
                return 1;
            }

        } else if (command == "view" && argc == 3) {
            std::string address = argv[2];
            auto id = store->load(address);
            if (id) {
                std::cout << id->toString() << "\n";
                return 0;
            } else {
quietPrint( "❌ Identity not found.\n");
                return 1;
            }

        } else if (command == "list") {
            auto all = store->getAll();
            for (const auto& id : all) {
                std::cout << id.toString() << "\n";
            }
            return 0;

        } else if (command == "delete" && argc == 3) {
            std::string address = argv[2];
            if (store->remove(address)) {
quietPrint( "✅ Identity deleted.\n");
                return 0;
            } else {
quietPrint( "❌ Failed to delete identity.\n");
                return 1;
            }

        } else if (command == "verify" && argc == 3) {
            std::string uuid = argv[2];
            auto id = store->load(uuid);
            if (!id) {
quietPrint( "❌ Identity not found.\n");
                return 1;
            }

            if (verifyIdentity(*id)) {
quietPrint( "✅ All verifications passed.\n");
                return 0;
            } else {
quietPrint( "❌ One or more verifications failed.\n");
                return 1;
            }

        } else {
quietPrint( "❌ Invalid command or arguments.\n");
            std::cerr << "Usage:\n"
                      << "  identitycli create <address> <displayName>\n"
                      << "  identitycli view <address>\n"
                      << "  identitycli list\n"
                      << "  identitycli delete <address>\n";
            return 1;
        }
    }

    // 🧑‍💻 Interactive terminal menu
    while (true) {
        printMenu();
        int choice;
        std::cin >> choice;
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        if (choice == 1) {
            std::string address, displayName;
            std::cout << "Enter wallet address: ";
            std::getline(std::cin, address);
            std::cout << "Enter display name: ";
            std::getline(std::cin, displayName);

            ZkIdentity id;
            id.uuid = address;
            id.name = displayName;
            id.publicKey = Crypto::getPublicKey(address);
            id.metadataHash = Crypto::hybridHash(displayName);
            id.createdAt = std::time(nullptr);
            id.generateZkProof();
            id.sign(address);

            if (store->save(id)) {
                std::cout << "✅ Identity created and saved.\n";
            } else {
quietPrint( "❌ Failed to save identity.\n");
            }

        } else if (choice == 2) {
            std::string address;
            std::cout << "Enter address: ";
            std::getline(std::cin, address);
            auto id = store->load(address);
            if (id) {
                std::cout << id->toString() << "\n";
            } else {
quietPrint( "❌ Identity not found.\n");
            }

        } else if (choice == 3) {
            auto all = store->getAll();
            for (const auto& id : all) {
                std::cout << id.toString() << "\n";
            }

        } else if (choice == 4) {
            std::string address;
            std::cout << "Enter address to delete: ";
            std::getline(std::cin, address);
            if (store->remove(address)) {
quietPrint( "✅ Identity deleted.\n");
            } else {
quietPrint( "❌ Failed to delete identity.\n");
            }

        } else if (choice == 5) {
            std::string address;
            std::cout << "Enter identity address to verify: ";
            std::getline(std::cin, address);
            auto id = store->load(address);
            if (!id) {
quietPrint( "❌ Identity not found.\n");
            } else {
                if (verifyIdentity(*id)) {
quietPrint( "✅ All verifications passed.\n");
                } else {
quietPrint( "❌ One or more verifications failed.\n");
                }
            }

        } else if (choice == 6) {
            break;

        } else {
            std::cout << "Invalid option. Try again.\n";
        }
    }

    return 0;
}
