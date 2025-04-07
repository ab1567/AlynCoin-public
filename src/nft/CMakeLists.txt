cmake_minimum_required(VERSION 3.10)
project(nftcli)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Paths
set(SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(ROOT_SRC_DIR ${CMAKE_SOURCE_DIR}/src)
set(GENERATED_DIR ${CMAKE_SOURCE_DIR}/src/generated)

# Include directories
include_directories(
    ${ROOT_SRC_DIR}
    ${ROOT_SRC_DIR}/nft
    ${ROOT_SRC_DIR}/nft/crypto
    ${ROOT_SRC_DIR}/zk
    ${ROOT_SRC_DIR}/db
    ${ROOT_SRC_DIR}/crypto
    ${GENERATED_DIR}
    /usr/include/jsoncpp
)

# OpenSSL dependency
find_package(OpenSSL REQUIRED)

# Add AES-256 crypto subdirectory (which has its own CMakeLists.txt)
add_subdirectory(${ROOT_SRC_DIR}/nft/crypto)

# Executable source files
add_executable(nftcli
    ${ROOT_SRC_DIR}/nft/main.cpp
    ${ROOT_SRC_DIR}/nft/nft_cli.cpp
    ${ROOT_SRC_DIR}/nft/nft.cpp
    ${ROOT_SRC_DIR}/nft/nft_storage.cpp
)

# Ensure core lib builds first
add_dependencies(nftcli alyncoin_lib)

# Link with AlynCoin core lib, AES crypto, and OpenSSL
target_link_libraries(nftcli
    alyncoin_lib
    nft_crypto
    OpenSSL::Crypto
)
