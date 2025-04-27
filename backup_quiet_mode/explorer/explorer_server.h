#ifndef EXPLORER_SERVER_H
#define EXPLORER_SERVER_H

#include <string>
#include <crow.h> // ⬅️ Required for `crow::response`
#include "explorer_db.h"
#include "../network/peer_blacklist.h"

class ExplorerServer {
private:
    ExplorerDB db;
    PeerBlacklist blacklist;
    int port;

public:
    ExplorerServer(int serverPort, const std::string& dbPath, const std::string& blacklistPath);
    void startServer(); // Starts HTTP server

private:
    // Endpoint Handlers
    std::string handleBlockRequest(const std::string& hash);
    std::string handleTransactionRequest(const std::string& hash);
    std::string handleAddressRequest(const std::string& address, int page, int limit);
    std::string handleStatsRequest();
    std::string handleBlockHeightRequest(int height);
    std::string handleLatestBlockRequest();
    std::string handleBlacklistRequest();

    // 🔓 CORS Wrapper
    crow::response withCORS(const std::string& body);  // ⬅️ Add this
};

#endif // EXPLORER_SERVER_H
