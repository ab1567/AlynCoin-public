#include "network.h"

void Network::requestEpochHeaders(const std::string& peerId) {
    sendData(peerId, "ALYN|REQUEST_EPOCH_HEADERS\n");
}
