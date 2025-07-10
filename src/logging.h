#pragma once
#include <spdlog/spdlog.h>
#include <sstream>
struct LogHelper {
  spdlog::level::level_enum level;
  const char* tag;
  std::ostringstream ss;
  LogHelper(spdlog::level::level_enum lvl, const char* t) : level(lvl), tag(t) {}
  ~LogHelper() { spdlog::log(level, "{} {}", tag, ss.str()); }
  template <typename T> LogHelper& operator<<(const T& v) {
    ss << v;
    return *this;
  }
  LogHelper& operator<<(std::ostream& (*pf)(std::ostream&)) {
    pf(ss);
    return *this;
  }
};
#define LOG_T(tag) LogHelper(spdlog::level::trace, tag)
#define LOG_D(tag) LogHelper(spdlog::level::debug, tag)
#define LOG_I(tag) LogHelper(spdlog::level::info, tag)
#define LOG_W(tag) LogHelper(spdlog::level::warn, tag)
#define LOG_E(tag) LogHelper(spdlog::level::err, tag)

