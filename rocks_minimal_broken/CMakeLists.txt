cmake_minimum_required(VERSION 3.10)
project(rocksdb_minimal)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

file(GLOB_RECURSE ROCKSDB_SRC CONFIGURE_DEPENDS
    src/*.cc
)

include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/include/rocksdb
    ${CMAKE_SOURCE_DIR}/include/rocksdb/db
    ${CMAKE_SOURCE_DIR}/include/rocksdb/db_impl
)


add_library(rocksdb_min STATIC ${ROCKSDB_SRC})

if(MINGW)
    target_compile_definitions(rocksdb_min PRIVATE OS_WIN)
    target_link_libraries(rocksdb_min PRIVATE ws2_32 shlwapi)
endif()
