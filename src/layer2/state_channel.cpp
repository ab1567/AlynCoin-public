#include "state_channel.h"
#include "../crypto_utils.h"
#include <sstream>

StateChannel::StateChannel()
    : channelId(""), participantA(""), participantB(""),
      balanceA(0.0), balanceB(0.0), isClosed(false) {}

StateChannel::StateChannel(const std::string& id, const std::string& a, const std::string& b, double balA, double balB)
    : channelId(id), participantA(a), participantB(b),
      balanceA(balA), balanceB(balB), isClosed(false) {}

void StateChannel::updateBalances(double deltaA, double deltaB) {
    balanceA += deltaA;
    balanceB += deltaB;
}

void StateChannel::closeChannel() {
    isClosed = true;
}

std::string StateChannel::getChannelHash() const {
    std::stringstream ss;
    ss << channelId << participantA << participantB << balanceA << balanceB << isClosed;
    for (const auto& tx : transactionHistory) {
        ss << tx;
    }
    return Crypto::sha256(ss.str());
}

bool StateChannel::verifySignatures() const {
    std::string hash = getChannelHash();
    return Crypto::verifySignature(participantA, signatureA, hash) &&
           Crypto::verifySignature(participantB, signatureB, hash);
}
