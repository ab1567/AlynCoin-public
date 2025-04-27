#include "explorer_utils.h"
#include <sstream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <crow.h>  // Crow included ONLY here

namespace ExplorerUtils {

    std::string formatBalance(double balance) {
        char buf[50];
        snprintf(buf, sizeof(buf), "%.8f", balance);
        return std::string(buf);
    }

    std::string trimHash(const std::string& hash) {
        if (hash.length() <= 12) return hash;
        return hash.substr(0, 6) + "..." + hash.substr(hash.length() - 6);
    }

    std::string jsonToString(const Json::Value& json) {
        Json::StreamWriterBuilder writer;
        writer["indentation"] = "  ";
        return Json::writeString(writer, json);
    }

    std::string formatTimestamp(std::time_t timestamp) {
        std::ostringstream oss;
        std::tm tm = *std::gmtime(&timestamp);
        oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S UTC");
        return oss.str();
    }

    Json::Value paginateJSON(const Json::Value& fullArray, int page, int limit) {
        Json::Value paginated(Json::arrayValue);
        int total = fullArray.size();
        int start = (page - 1) * limit;
        int end = std::min(start + limit, total);

        for (int i = start; i < end; ++i) {
            paginated.append(fullArray[i]);
        }
        return paginated;
    }

    std::pair<int, int> calculatePagination(int page, int limit, int totalItems) {
        int start = (page - 1) * limit;
        int end = std::min(start + limit, totalItems);
        if (start >= totalItems) {
            start = 0;
            end = 0;
        }
        return { start, end };
    }

    // Now safely put parseQueryParam here, no Crow in header
    int parseQueryParam(const crow::query_string& params, const std::string& key, int defaultValue) {
        if (params.get(key) != nullptr) {
            try {
                return std::stoi(params.get(key));
            } catch (...) {
                return defaultValue;
            }
        }
        return defaultValue;
    }

}
