#include "metrics_server.h"
#include "transport/peer_globals.h"
#include <crow.h>
#include <json/json.h>
#include <mutex>

MetricsServer::MetricsServer(int p) : port(p) {}

void MetricsServer::startServer() {
    crow::SimpleApp app;

    CROW_ROUTE(app, "/metrics")([]() {
        Json::Value root(Json::arrayValue);
        {
            std::lock_guard<std::timed_mutex> lock(peersMutex);
            for (const auto &kv : peerTransports) {
                Json::Value j;
                j["peer"] = kv.first;
                if (kv.second.state) {
                    j["mis_score"] = kv.second.state->misScore;
                    j["frame_rate"] = Json::UInt64(kv.second.state->frameCountMin);
                    j["byte_rate"] = Json::UInt64(kv.second.state->byteCountMin);
                }
                root.append(j);
            }
        }
        Json::StreamWriterBuilder w; w["indentation"] = "  ";
        return crow::response(Json::writeString(w, root));
    });

    app.port(port).multithreaded().run();
}
