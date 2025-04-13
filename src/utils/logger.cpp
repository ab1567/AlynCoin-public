#include "logger.h"

void Logger::info(const std::string& msg) {
    std::cout << "ℹ️  " << msg << std::endl;
}

void Logger::warn(const std::string& msg) {
    std::cout << "⚠️  " << msg << std::endl;
}

void Logger::error(const std::string& msg) {
    std::cerr << "❌ " << msg << std::endl;
}

void Logger::success(const std::string& msg) {
    std::cout << "✅ " << msg << std::endl;
}
