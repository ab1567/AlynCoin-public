#pragma once
#include <spdlog/spdlog.h>

#ifdef ENABLE_NET_TRACE
  #define NET_TRACE(...) spdlog::debug(__VA_ARGS__)
#else
  #define NET_TRACE(...) (void)0
#endif
