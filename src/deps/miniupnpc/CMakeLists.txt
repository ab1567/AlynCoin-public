add_library(miniupnpc STATIC miniupnpc_stub.c)
target_include_directories(miniupnpc PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
