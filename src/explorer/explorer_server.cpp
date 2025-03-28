#include "explorer_server.h"
#include "explorer_utils.h"
#include "network/peer_blacklist.h" // ✅ Include PeerBlacklist
#include <crow.h>
#include <iostream>

ExplorerServer::ExplorerServer(int serverPort, const std::string& dbPath, const std::string& blacklistPath)
    : port(serverPort), db(dbPath), blacklist(blacklistPath) // ✅ Pass DB and Blacklist paths
{}

void ExplorerServer::startServer() {
    crow::SimpleApp app;

    // =======================
    // Endpoint: Get Block by Hash
    CROW_ROUTE(app, "/block/<string>")
    ([this](const crow::request&, std::string hash) {
        return handleBlockRequest(hash);
    });

    // =======================
    // Endpoint: Get Transaction by Hash
    CROW_ROUTE(app, "/tx/<string>")
    ([this](const crow::request&, std::string hash) {
        return handleTransactionRequest(hash);
    });

    // =======================
    // Endpoint: Get Address Details with Pagination
    CROW_ROUTE(app, "/address/<string>").methods("GET"_method)
    ([this](const crow::request& req, std::string address) {
        int page = ExplorerUtils::parseQueryParam(req.url_params, "page", 1);
        int limit = ExplorerUtils::parseQueryParam(req.url_params, "limit", 10);
        return handleAddressRequest(address, page, limit);
    });

    // =======================
    // Endpoint: Blockchain Stats
    CROW_ROUTE(app, "/stats")
    ([this](const crow::request&) {
        return handleStatsRequest();
    });

    // =======================
    // Endpoint: Get Block by Height
    CROW_ROUTE(app, "/block/height/<int>")
    ([this](const crow::request&, int height) {
        return handleBlockHeightRequest(height);
    });

    // =======================
    // Endpoint: Latest Block
    CROW_ROUTE(app, "/latestblock")
    ([this](const crow::request&) {
        return handleLatestBlockRequest();
    });

    // =======================
    // Endpoint: View Blacklist
    CROW_ROUTE(app, "/blacklist")
    ([this](const crow::request&) {
        return handleBlacklistRequest();
    });

    // =======================
    std::cout << "\U0001F680 Blockchain Explorer Server running on port " << port << "\n";
    app.port(port).multithreaded().run();
}

// ======= Handlers =======

std::string ExplorerServer::handleBlockRequest(const std::string& hash) {
    Json::Value block = db.getBlockByHash(hash);
    if (block.isNull()) return "Block not found!";
    return ExplorerUtils::jsonToString(block);
}

std::string ExplorerServer::handleTransactionRequest(const std::string& hash) {
    Json::Value tx = db.getTransactionByHash(hash);
    if (tx.isNull()) return "Transaction not found!";
    return ExplorerUtils::jsonToString(tx);
}

std::string ExplorerServer::handleAddressRequest(const std::string& address, int page, int limit) {
    Json::Value response;
    double balance = db.getBalance(address);
    Json::Value allTxs = db.getTransactionsByAddress(address);

    Json::Value pagedTxs(Json::arrayValue);
    int totalTxs = allTxs.size();

    auto [start, end] = ExplorerUtils::calculatePagination(page, limit, totalTxs);

    for (int i = start; i < end; ++i) {
        pagedTxs.append(allTxs[i]);
    }

    response["address"] = address;
    response["balance"] = ExplorerUtils::formatBalance(balance);
    response["transactions"] = pagedTxs;
    response["page"] = page;
    response["totalTxs"] = totalTxs;

    return ExplorerUtils::jsonToString(response);
}

std::string ExplorerServer::handleStatsRequest() {
    Json::Value stats = db.getBlockchainStats();
    return ExplorerUtils::jsonToString(stats);
}

std::string ExplorerServer::handleBlockHeightRequest(int height) {
    Json::Value block = db.getBlockByHeight(height);
    if (block.isNull()) return "Block not found!";
    return ExplorerUtils::jsonToString(block);
}

std::string ExplorerServer::handleLatestBlockRequest() {
    Json::Value block = db.getLatestBlock();
    if (block.isNull()) return "No blocks yet!";
    return ExplorerUtils::jsonToString(block);
}

// ✅ New Blacklist Handler
std::string ExplorerServer::handleBlacklistRequest() {
    Json::Value result(Json::arrayValue);
    auto entries = blacklist.getAllEntries();
    for (const auto& entry : entries) {
        Json::Value item;
        item["peer_id"] = entry.peer_id;
        item["strikes"] = entry.strikes;
        item["reason"] = entry.reason;
        item["timestamp"] = entry.timestamp;
        result.append(item);
    }
    return ExplorerUtils::jsonToString(result);
}

// ✅ Add missing main function
int main() {
    int port = 8080;
    std::string dbPath = "/root/.alyncoin/db";
    std::string blacklistPath = "/root/.alyncoin/blacklist";

    ExplorerServer server(port, dbPath, blacklistPath);
    server.startServer();

    return 0;
}
