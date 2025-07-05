#include "metrics_server.h"

int main() {
    MetricsServer server(9100);
    server.startServer();
    return 0;
}
