#include "identity_store.h"
#include "../crypto_utils.h"
#include "proto_utils.h"
#include <iostream>
#include <memory>
#include <string>
#include <map>
#include <limits>

void printMenu() {
    std::cout << "\n[ zk-Identity CLI Menu ]\n"
              << "1. Create Identity\n"
              << "2. View Identity\n"
              << "3. List All Identities\n"
              << "4. Delete Identity\n"
              << "5. Exit\n"
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
                std::cerr << "❌ Failed to save identity.\n";
                return 1;
            }

        } else if (command == "view" && argc == 3) {
            std::string address = argv[2];
            auto id = store->load(address);
            if (id) {
                std::cout << id->toString() << "\n";
                return 0;
            } else {
                std::cerr << "❌ Identity not found.\n";
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
                std::cout << "✅ Identity deleted.\n";
                return 0;
            } else {
                std::cerr << "❌ Failed to delete identity.\n";
                return 1;
            }

        } else {
            std::cerr << "❌ Invalid command or arguments.\n";
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
                std::cout << "❌ Failed to save identity.\n";
            }

        } else if (choice == 2) {
            std::string address;
            std::cout << "Enter address: ";
            std::getline(std::cin, address);
            auto id = store->load(address);
            if (id) {
                std::cout << id->toString() << "\n";
            } else {
                std::cout << "❌ Identity not found.\n";
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
                std::cout << "✅ Identity deleted.\n";
            } else {
                std::cout << "❌ Failed to delete identity.\n";
            }

        } else if (choice == 5) {
            break;

        } else {
            std::cout << "Invalid option. Try again.\n";
        }
    }

    return 0;
}
