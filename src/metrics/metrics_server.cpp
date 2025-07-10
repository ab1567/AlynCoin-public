#include "metrics_server.h"
#include "transport/peer_globals.h"
#include "core/Metrics.hpp"
#include <sstream>
#include <crow.h>
#include <mutex>

MetricsServer::MetricsServer(int p) : port(p) {}

void MetricsServer::startServer() {
    crow::SimpleApp app;

    CROW_ROUTE(app, "/metrics")([]() {
        std::ostringstream out;
        out << "pending_block_verifications "
            << Metrics::pending_block_verifications.load() << "\n";
        out << "broadcast_queue_len "
            << Metrics::broadcast_queue_len.load() << "\n";
        return crow::response(out.str());
    });

    app.port(port).multithreaded().run();
}
