#ifndef METRICS_SERVER_H
#define METRICS_SERVER_H
#include <string>

class MetricsServer {
    int port;
public:
    explicit MetricsServer(int p);
    void startServer();
};

#endif // METRICS_SERVER_H
