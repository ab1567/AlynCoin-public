#ifndef EXPLORER_UTILS_H
#define EXPLORER_UTILS_H

#include <string>
#include <json/json.h>
#include <ctime>
#include <crow.h>

namespace ExplorerUtils {

    std::string formatBalance(double balance);

    std::string trimHash(const std::string& hash);

    std::string jsonToString(const Json::Value& json);

    std::string formatTimestamp(std::time_t timestamp);

    Json::Value paginateJSON(const Json::Value& fullArray, int page, int limit);

    std::pair<int, int> calculatePagination(int page, int limit, int totalItems);

    int parseQueryParam(const crow::query_string& params, const std::string& key, int defaultValue);
}

#endif // EXPLORER_UTILS_H
