#include "nft_cli.h"
#include <sodium.h>
#include <cstdio>

int main(int argc, char** argv) {
    if (sodium_init() < 0) {
        std::fprintf(stderr, "sodium_init failed\n");
        return 1;
    }
    return NFTCLI::handleCommand(argc, argv);
}
