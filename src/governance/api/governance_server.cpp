#include "crow_all.h"
#include "dao_api.cpp"

int main() {
    crow::SimpleApp app;

    // Setup Governance DAO API endpoints
    setupGovernanceAPI(app);

    std::cout << "Governance API server running at http://localhost:8080\n";

    app.port(8080).multithreaded().run();
}
