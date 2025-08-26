#include <iostream>
#include <string>
#include <cstdlib>

void printUsage() {
    std::cout << "Usage: bridgecli <command> [args]\n";
    std::cout << "Commands:\n";
    std::cout << "  lock <evmAddr> <amount>\n";
    std::cout << "  mint <lockTxHash>\n";
    std::cout << "  burn <amount>\n";
    std::cout << "  release <burnTxHash>\n";
    std::cout << "  stats\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printUsage();
        return 1;
    }

    std::string cmd = argv[1];

    if (cmd == "lock" && argc == 4) {
        std::string evmAddr = argv[2];
        std::string amount = argv[3];
        std::string command = "python3 bridge/bridge_cli.py lock " + evmAddr + " " + amount;
        return std::system(command.c_str());
    } else if (cmd == "mint" && argc == 3) {
        std::string tx = argv[2];
        std::string command = "python3 bridge/bridge_cli.py mint --tx " + tx;
        return std::system(command.c_str());
    } else if (cmd == "burn" && argc == 3) {
        std::string amount = argv[2];
        std::string command = "python3 bridge/bridge_cli.py burn " + amount;
        return std::system(command.c_str());
    } else if (cmd == "release" && argc == 3) {
        std::string tx = argv[2];
        std::string command = "python3 bridge/bridge_cli.py release --tx " + tx;
        return std::system(command.c_str());
    } else if (cmd == "stats" && argc == 2) {
        std::string command = "python3 bridge/bridge_cli.py stats";
        return std::system(command.c_str());
    }

    printUsage();
    return 1;
}

