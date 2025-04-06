cmake_minimum_required(VERSION 3.10)
project(nftcli)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# --------------------------
# Path Setup
set(SOURCE_DIR ${CMAKE_SOURCE_DIR}/..)
set(GENERATED_DIR ${SOURCE_DIR}/generated)

# --------------------------
# Include Directories
include_directories(
    ${SOURCE_DIR}
    ${SOURCE_DIR}/nft
    ${SOURCE_DIR}/db
    ${SOURCE_DIR}/zk
    ${GENERATED_DIR}
    ${SOURCE_DIR}/crypto/falcon/PQClean/Falcon-1024/clean
    ${SOURCE_DIR}/crypto/falcon/PQClean/common
    ${SOURCE_DIR}/crypto/falcon/PQClean/common/keccak4x
    ${SOURCE_DIR}/crypto/dilithium
    ${SOURCE_DIR}/crypto/dilithium/ref
    /usr/include/jsoncpp
    /usr/include/rocksdb
    /usr/include/nlohmann
)

# --------------------------
# Dependencies
find_package(OpenSSL REQUIRED)
find_package(Protobuf REQUIRED)
find_library(ROCKSDB_LIB rocksdb REQUIRED)
find_library(JSONCPP_LIB jsoncpp REQUIRED)

# --------------------------
# Falcon + Dilithium Static Libraries
file(GLOB FALCON_SOURCES
    ${SOURCE_DIR}/crypto/falcon/PQClean/Falcon-1024/clean/*.c
    ${SOURCE_DIR}/crypto/falcon/PQClean/common/*.c
    ${SOURCE_DIR}/crypto/falcon/PQClean/common/keccak4x/*.c
)

file(GLOB DILITHIUM_SOURCES
    ${SOURCE_DIR}/crypto/dilithium/*.c
    ${SOURCE_DIR}/crypto/dilithium/ref/*.c
)

add_library(falcon STATIC ${FALCON_SOURCES})
add_library(dilithium STATIC ${DILITHIUM_SOURCES})

# --------------------------
# NFT CLI Source Files
set(NFT_SOURCES
    ${SOURCE_DIR}/nft/main.cpp
    ${SOURCE_DIR}/nft/nft.cpp
    ${SOURCE_DIR}/nft/nft_storage.cpp
    ${SOURCE_DIR}/nft/nft_cli.cpp
    ${SOURCE_DIR}/nft/nft_zk.cpp
    ${SOURCE_DIR}/zk/winterfell_stark.cpp
    ${SOURCE_DIR}/crypto_utils.cpp
    ${GENERATED_DIR}/nft.pb.cc
)

# --------------------------
# Executable
add_executable(nftcli ${NFT_SOURCES})

# --------------------------
# Link Dependencies
target_link_libraries(nftcli
    ${Protobuf_LIBRARIES}
    ${ROCKSDB_LIB}
    ${JSONCPP_LIB}
    OpenSSL::Crypto
    falcon
    dilithium
    pthread
    crypto
    m
    dl
)

# --------------------------
# Output Message
message(STATUS "✅ NFT CLI Build Configured with Falcon, Dilithium, zk-STARK, RocksDB, and Protobuf")
