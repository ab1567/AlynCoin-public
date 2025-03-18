#ifndef SYNCING_H
#define SYNCING_H

#include "block.h"
#include "transaction.h"
#include "network.h"

class Syncing {
public:
    static void requestLatestBlock();
    static void syncWithNetwork();
    static void propagateBlock(const Block& block);
    static void propagateTransaction(const Transaction& tx);
};

#endif // SYNCING_H
