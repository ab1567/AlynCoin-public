#ifndef LAYER2_ROLLUPS_H
#define LAYER2_ROLLUPS_H

#include <string>
#include <vector>

class Rollup {
public:
    Rollup(std::string rollupId, int batchSize);
    bool addTransaction(const std::string& transaction);
    bool submitToLayer1();

private:
    std::string rollupId;
    int batchSize;
    std::vector<std::string> transactions;
};

#endif // LAYER2_ROLLUPS_H
