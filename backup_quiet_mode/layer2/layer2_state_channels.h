#ifndef LAYER2_STATE_CHANNELS_H
#define LAYER2_STATE_CHANNELS_H

#include <string>

class StateChannel {
public:
    StateChannel(std::string channelId, std::string participant1, std::string participant2);
    bool submitOffChainTransaction(const std::string& transactionData);
    bool settleChannel();

private:
    std::string channelId;
    std::string participant1;
    std::string participant2;
};

#endif // LAYER2_STATE_CHANNELS_H
