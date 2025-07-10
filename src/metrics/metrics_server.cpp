#include "metrics_server.h"
#include "transport/peer_globals.h"
#include "core/Metrics.hpp"
#include "logging.h"
#include <sstream>
#include <crow.h>
#include <mutex>

MetricsServer::MetricsServer(int p) : port(p) {}

void MetricsServer::startServer() {
    crow::SimpleApp app;

    CROW_ROUTE(app, "/metrics")([]() {
        std::ostringstream out;
        auto pending = Metrics::pending_block_verifications.load();
        auto qlen = Metrics::broadcast_queue_len.load();
        out << "pending_block_verifications " << pending << "\n";
        out << "broadcast_queue_len " << qlen << "\n";
        LOG_I("[metrics]") << "pending_block_verifications=" << pending
                           << " broadcast_queue_len=" << qlen;
        return crow::response(out.str());
    });

    app.port(port).multithreaded().run();
}
