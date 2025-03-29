#include "explorer_server.h"
#include "explorer_utils.h"
#include "network/peer_blacklist.h"
#include <crow.h>
#include <iostream>
#include "db/db_paths.h"

ExplorerServer::ExplorerServer(int serverPort, const std::string& dbPath, const std::string& blacklistPath)
    : port(serverPort), db(dbPath), blacklist(blacklistPath) {}

void ExplorerServer::startServer() {
    crow::SimpleApp app;

    // 🏁 Root Greeting
    CROW_ROUTE(app, "/")
    ([this](const crow::request&) {
        return withCORS("🧠 AlynCoin Blockchain Explorer API — use /stats, /block/<hash>, /tx/<hash>, /address/<addr>");
    });

    // 📊 Blockchain Stats
    CROW_ROUTE(app, "/stats")
    ([this](const crow::request&) {
        return withCORS(handleStatsRequest());
    });

    // 🔍 Block by Hash
    CROW_ROUTE(app, "/block/<string>")
    ([this](const crow::request&, std::string hash) {
        return withCORS(handleBlockRequest(hash));
    });

    // 🔢 Block by Height
    CROW_ROUTE(app, "/block/height/<int>")
    ([this](const crow::request&, int height) {
        return withCORS(handleBlockHeightRequest(height));
    });

    // 🧱 Latest Block
    CROW_ROUTE(app, "/latestblock")
    ([this](const crow::request&) {
        return withCORS(handleLatestBlockRequest());
    });

    // 📨 Transaction by Hash
    CROW_ROUTE(app, "/tx/<string>")
    ([this](const crow::request&, std::string hash) {
        return withCORS(handleTransactionRequest(hash));
    });

    // 👛 Address Info with Pagination
    CROW_ROUTE(app, "/address/<string>").methods("GET"_method)
    ([this](const crow::request& req, std::string address) {
        int page = ExplorerUtils::parseQueryParam(req.url_params, "page", 1);
        int limit = ExplorerUtils::parseQueryParam(req.url_params, "limit", 10);
        return withCORS(handleAddressRequest(address, page, limit));
    });

    // 💰 Basic Balance Check
    CROW_ROUTE(app, "/balance/<string>")
    ([this](const crow::request&, std::string address) {
        double balance = db.getBalance(address);
        Json::Value result;
        result["address"] = address;
        result["balance"] = ExplorerUtils::formatBalance(balance);
        return withCORS(ExplorerUtils::jsonToString(result));
    });

    // 🚫 Blacklist View
    CROW_ROUTE(app, "/blacklist")
    ([this](const crow::request&) {
        return withCORS(handleBlacklistRequest());
    });

    // ⚙️ OPTIONS Preflight (CORS support)
    CROW_ROUTE(app, "/<string>").methods("OPTIONS"_method)
    ([](const crow::request&, std::string) {
        crow::response res;
        res.add_header("Access-Control-Allow-Origin", "*");
        res.add_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        res.add_header("Access-Control-Allow-Headers", "Content-Type");
        return res;
    });

    std::cout << "🚀 Blockchain Explorer Server running on port " << port << "\n";
    app.port(port).multithreaded().run();
}

// ======= Handlers =======

std::string ExplorerServer::handleBlockRequest(const std::string& hash) {
    std::string normalizedHash = hash;
    std::transform(normalizedHash.begin(), normalizedHash.end(), normalizedHash.begin(), ::tolower);

    Json::Value block = db.getBlockByHash(normalizedHash);
    if (block.isNull()) {
        Json::Value err;
        err["error"] = "Block not found";
        return ExplorerUtils::jsonToString(err);
    }
    return ExplorerUtils::jsonToString(block);
}

std::string ExplorerServer::handleTransactionRequest(const std::string& hash) {
    Json::Value tx = db.getTransactionByHash(hash);
    if (tx.isNull()) {
        Json::Value err;
        err["error"] = "Transaction not found";
        return ExplorerUtils::jsonToString(err);
    }
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
    if (block.isNull()) {
        Json::Value err;
        err["error"] = "Block not found";
        return ExplorerUtils::jsonToString(err);
    }
    return ExplorerUtils::jsonToString(block);
}

std::string ExplorerServer::handleLatestBlockRequest() {
    Json::Value block = db.getLatestBlock();
    if (block.isNull()) {
        Json::Value info;
        info["info"] = "No blocks yet";
        return ExplorerUtils::jsonToString(info);
    }
    return ExplorerUtils::jsonToString(block);
}

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

// ======= CORS Helper =======

crow::response ExplorerServer::withCORS(const std::string& body) {
    crow::response res(body);
    res.add_header("Access-Control-Allow-Origin", "*");
    res.add_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.add_header("Access-Control-Allow-Headers", "Content-Type");
    return res;
}

// ======= Main Entry Point =======

int main() {
    int port = 8080;
    std::string dbPath = DBPaths::getBlockchainDB();  // Ensure this matches node's DB
    std::string blacklistPath = "/root/.alyncoin/blacklist";

    ExplorerServer server(port, dbPath, blacklistPath);
    server.startServer();
    return 0;
}
