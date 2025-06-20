#pragma once
#include <string_view>
#include <cstddef>

/* 64 lower-case hex zeros – canonical “null” parent-hash */
inline constexpr std::string_view GENESIS_PARENT_HASH =
    "0000000000000000000000000000000000000000000000000000000000000000";

inline constexpr int DESYNC_THRESHOLD = 5000;
