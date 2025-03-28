#ifndef TRANSACTION_VALIDATOR_H
#define TRANSACTION_VALIDATOR_H

#include <string>
#include "../network/peer_blacklist.h"

class TransactionValidator {
private:
    PeerBlacklist* blacklist;

public:
    TransactionValidator(PeerBlacklist* bl);

    bool validateTransaction(const std::string& tx_data, const std::string& peer_id);
};

#endif // TRANSACTION_VALIDATOR_H
