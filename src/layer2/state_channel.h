#ifndef STATE_CHANNEL_H
#define STATE_CHANNEL_H

#include <string>
#include <vector>

class StateChannel {
public:
    std::string channelId;
    std::string participantA;
    std::string participantB;
    double balanceA;
    double balanceB;
    std::vector<std::string> transactionHistory;
    std::string signatureA;
    std::string signatureB;
    bool isClosed;

    StateChannel();
    StateChannel(const std::string& id, const std::string& a, const std::string& b, double balA, double balB);

    void updateBalances(double deltaA, double deltaB);
    void closeChannel();
    std::string getChannelHash() const;
    bool verifySignatures() const;
};

#endif // STATE_CHANNEL_H
