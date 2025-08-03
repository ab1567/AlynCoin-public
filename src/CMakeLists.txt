cmake_minimum_required(VERSION 3.10)
project(alyncoin)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# -----------------------------------------
# Protobuf: Ensure static linking and use pkg-config for dependencies
set(Protobuf_USE_STATIC_LIBS ON)
set(Protobuf_USE_STATIC_LIBS_INIT ON)

# --------------------------
# Detect CPU Architecture
include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)

message(STATUS "Detecting CPU Architecture...")

set(ARCHITECTURE "Generic")
set(SIMD_FLAGS "")

if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
    set(ARCHITECTURE "x86_64")
    message(STATUS "Compiling for x86_64 (BLAKE3 SSE4.1 & AVX2 optimizations enabled)")
    add_compile_definitions(USE_SSE4_1 USE_AVX2)
    set(SIMD_FLAGS "-msse4.1 -mavx2")

    check_cxx_compiler_flag("-mavx512f" HAS_AVX512)
    if(HAS_AVX512)
        message(WARNING "AVX-512 detected but DISABLED to prevent linker errors.")
        set(AVX512_DISABLED TRUE)
    endif()

elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
    set(ARCHITECTURE "ARM64")
    message(STATUS "Compiling for ARM64 (Portable BLAKE3 implementation)")
    add_compile_definitions(USE_ARM_NEON)

elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "arm")
    set(ARCHITECTURE "ARM")
    message(STATUS "Compiling for ARM (32-bit) - Portable BLAKE3 Implementation")
    add_compile_definitions(USE_ARM_NEON)

else()
    message(WARNING "Unknown architecture detected - Using Portable BLAKE3 implementation")
endif()

# --------------------------
# Directories
set(SOURCE_DIR ${CMAKE_SOURCE_DIR}/src)
set(GENERATED_DIR ${CMAKE_BINARY_DIR}/generated)
file(MAKE_DIRECTORY ${GENERATED_DIR})

# --------------------------
# Core Source Files
file(GLOB SOURCES
    ${SOURCE_DIR}/block.cpp
    ${SOURCE_DIR}/blockchain.cpp
    ${SOURCE_DIR}/transaction.cpp
    ${SOURCE_DIR}/network.cpp
    ${SOURCE_DIR}/crypto_utils.cpp
    ${SOURCE_DIR}/crypto/sphinx.cpp
    ${SOURCE_DIR}/miner.cpp
    ${SOURCE_DIR}/wallet.cpp
    ${SOURCE_DIR}/keccak.cpp
    ${SOURCE_DIR}/key_paths.cpp
    ${SOURCE_DIR}/consensus/difficulty.cpp
    ${SOURCE_DIR}/consensus/fork_choice.cpp
    ${SOURCE_DIR}/zk/*.cpp
    ${SOURCE_DIR}/rollup/rollup_block.cpp
    ${SOURCE_DIR}/rollup/rollup_utils.cpp
    ${SOURCE_DIR}/rollup/proofs/*.cpp
    ${SOURCE_DIR}/rollup/circuits/*.cpp
    ${SOURCE_DIR}/network/peer_blacklist.cpp
    ${SOURCE_DIR}/network/peer_manager.cpp
    ${SOURCE_DIR}/validation/transaction_validator.cpp
    ${SOURCE_DIR}/governance/dao.cpp
    ${SOURCE_DIR}/governance/dao_storage.cpp
    ${SOURCE_DIR}/governance/devfund.cpp
)

list(APPEND SOURCES
    ${SOURCE_DIR}/self_healing/health_monitor.cpp
    ${SOURCE_DIR}/self_healing/sync_recovery.cpp
    ${SOURCE_DIR}/self_healing/self_healing_node.cpp
    ${SOURCE_DIR}/utils/logger.cpp
)

list(APPEND SOURCES
    ${SOURCE_DIR}/identity/identity.cpp
    ${SOURCE_DIR}/identity/identity_store.cpp
    ${SOURCE_DIR}/identity/proto_utils.cpp
)

list(APPEND SOURCES
    ${SOURCE_DIR}/db/rocksdb_wrapper.cpp
    ${SOURCE_DIR}/db/db_instance.cpp
    ${SOURCE_DIR}/db/db_writer.cpp
)

list(APPEND SOURCES
    ${SOURCE_DIR}/nft/nft.cpp
    ${SOURCE_DIR}/nft/nft_storage.cpp
    ${SOURCE_DIR}/nft/crypto/aes_utils.cpp
    ${SOURCE_DIR}/nft/nft_utils.cpp
)

list(APPEND SOURCES
    ${SOURCE_DIR}/transport/transport.h
    ${SOURCE_DIR}/transport/tcp_transport.cpp
    ${SOURCE_DIR}/transport/tcp_transport.h
    ${SOURCE_DIR}/transport/ssl_transport.cpp
    ${SOURCE_DIR}/transport/ssl_transport.h
    ${SOURCE_DIR}/transport/pubsub_router.cpp
    ${SOURCE_DIR}/transport/pubsub_router.h
    ${SOURCE_DIR}/transport/peer_globals.cpp
    ${SOURCE_DIR}/epoch_sync.cpp
    ${SOURCE_DIR}/syncing/headers_sync.cpp
    ${SOURCE_DIR}/syncing/orphan_pool.cpp
    ${SOURCE_DIR}/config.cpp
    ${SOURCE_DIR}/tls_utils.cpp
)

file(GLOB EXPLORER_SOURCES ${SOURCE_DIR}/explorer/*.cpp)
file(GLOB METRICS_SOURCES ${SOURCE_DIR}/metrics/*.cpp)
file(GLOB RPC_SOURCES ${SOURCE_DIR}/rpc/*.cpp)

list(APPEND SOURCES
    ${RPC_SOURCES}
)

set(MAIN_SOURCE ${SOURCE_DIR}/main.cpp)

# --------------------------
# BLAKE3 Sources
set(BLAKE3_SOURCES
    ${SOURCE_DIR}/blake3.c
    ${SOURCE_DIR}/blake3_dispatch.c
    ${SOURCE_DIR}/blake3_portable.c
    ${SOURCE_DIR}/blake3_sse2.c
    ${SOURCE_DIR}/blake3_sse41.c
    ${SOURCE_DIR}/blake3_avx2.c
)

if(AVX512_DISABLED)
    add_compile_definitions(BLAKE3_NO_AVX512)
    set_source_files_properties(${SOURCE_DIR}/blake3_dispatch.c PROPERTIES COMPILE_DEFINITIONS "BLAKE3_NO_AVX512")
endif()

# --------------------------
# Include Directories
include_directories(
    ${CMAKE_BINARY_DIR}
    ${GENERATED_DIR}
    ${SOURCE_DIR}
    ${SOURCE_DIR}/zk
    ${SOURCE_DIR}/rollup
    ${SOURCE_DIR}/rollup/proofs
    ${SOURCE_DIR}/rollup/circuits
    ${SOURCE_DIR}/explorer
    ${SOURCE_DIR}/deps/CrowInclude
    /usr/include/jsoncpp
    /usr/include/rocksdb
    ${SOURCE_DIR}/crypto/falcon/PQClean/Falcon-1024/clean
    ${SOURCE_DIR}/crypto/falcon/PQClean/common
    ${SOURCE_DIR}/crypto/dilithium
    ${SOURCE_DIR}/crypto/dilithium/ref
    ${SOURCE_DIR}/atomic_swaps
    ${SOURCE_DIR}/identity
    ${SOURCE_DIR}/self_healing
    ${SOURCE_DIR}/utils
    ${SOURCE_DIR}/network
    ${SOURCE_DIR}/metrics
    ${SOURCE_DIR}/rpc
)

# --------------------------
# Dependencies
find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(JSONCPP jsoncpp)
find_package(Protobuf REQUIRED)
find_package(absl REQUIRED)
find_library(SODIUM_LIB sodium REQUIRED)
find_path(SODIUM_INCLUDE_DIR sodium.h)
include_directories(${SODIUM_INCLUDE_DIR})
find_library(ROCKSDB_LIB rocksdb REQUIRED)
find_path(ROCKSDB_INCLUDE_DIR rocksdb/db.h)

include_directories(${ROCKSDB_INCLUDE_DIR})

# ---- miniupnpc (UPnP) ----
find_path(MINIUPNPC_INCLUDE_DIR miniupnpc/miniupnpc.h)
find_library(MINIUPNPC_LIBRARY NAMES miniupnpc libminiupnpc)

if(MINIUPNPC_INCLUDE_DIR AND MINIUPNPC_LIBRARY)
    message(STATUS "miniupnpc found: ${MINIUPNPC_LIBRARY}")
    set(HAVE_MINIUPNPC TRUE)
    set(UPNP_LIB ${MINIUPNPC_LIBRARY})
else()
    message(WARNING "miniupnpc not found, UPnP will be disabled!")
    set(HAVE_MINIUPNPC FALSE)
    set(UPNP_LIB "")
endif()

find_path(NATPMP_INCLUDE_DIR natpmp.h)
find_library(NATPMP_LIBRARY NAMES natpmp libnatpmp)

if(NATPMP_INCLUDE_DIR AND NATPMP_LIBRARY)
    message(STATUS "libnatpmp found: ${NATPMP_LIBRARY}")
    add_definitions(-DHAVE_LIBNATPMP)
    include_directories(${NATPMP_INCLUDE_DIR})
else()
    message(WARNING "libnatpmp not found, NAT-PMP will be disabled!")
endif()

# --------------------------
# Only generate protobufs if not skipped
if(NOT SKIP_PROTOBUF_GEN)

    set(PROTO_SRCS
        ${GENERATED_DIR}/sync_protos.pb.cc
        ${GENERATED_DIR}/block_protos.pb.cc
        ${GENERATED_DIR}/blockchain_protos.pb.cc
        ${GENERATED_DIR}/crypto_protos.pb.cc
        ${GENERATED_DIR}/transaction_protos.pb.cc
        ${GENERATED_DIR}/main_protos.pb.cc
        ${GENERATED_DIR}/nft.pb.cc
        ${GENERATED_DIR}/atomic_swap.pb.cc
        ${GENERATED_DIR}/identity.pb.cc
        ${GENERATED_DIR}/net_frame.pb.cc
    )

    set(PROTO_HEADERS
        ${GENERATED_DIR}/sync_protos.pb.h
        ${GENERATED_DIR}/block_protos.pb.h
        ${GENERATED_DIR}/blockchain_protos.pb.h
        ${GENERATED_DIR}/crypto_protos.pb.h
        ${GENERATED_DIR}/transaction_protos.pb.h
        ${GENERATED_DIR}/main_protos.pb.h
        ${GENERATED_DIR}/nft.pb.h
        ${GENERATED_DIR}/atomic_swap.pb.h
        ${GENERATED_DIR}/identity.pb.h
        ${GENERATED_DIR}/net_frame.pb.h
    )

    add_custom_command(
        OUTPUT ${PROTO_HEADERS} ${PROTO_SRCS}
        COMMAND ${Protobuf_PROTOC_EXECUTABLE} --proto_path=${SOURCE_DIR}/proto
                --cpp_out=${GENERATED_DIR}
                --experimental_allow_proto3_optional
                ${SOURCE_DIR}/proto/sync_protos.proto
                ${SOURCE_DIR}/proto/block_protos.proto
                ${SOURCE_DIR}/proto/blockchain_protos.proto
                ${SOURCE_DIR}/proto/crypto_protos.proto
                ${SOURCE_DIR}/proto/transaction_protos.proto
                ${SOURCE_DIR}/proto/main_protos.proto
                ${SOURCE_DIR}/proto/nft.proto
                ${SOURCE_DIR}/proto/atomic_swap.proto
                ${SOURCE_DIR}/proto/identity.proto
                ${SOURCE_DIR}/proto/net_frame.proto
        DEPENDS ${SOURCE_DIR}/proto/*.proto
        COMMENT "Generating Protobuf files..."
    )

    add_custom_target(protobuf_gen DEPENDS ${PROTO_SRCS})

endif()

# --------------------------
# Winterfell Rust FFI
add_custom_target(winterfell_ffi ALL
    COMMAND cargo build --release
    WORKING_DIRECTORY ${SOURCE_DIR}/rust
    COMMENT "Building Winterfell zk-STARK Rust FFI..."
)

# === Falcon Static Library ===
file(GLOB FALCON_CLEAN_SOURCES
    ${SOURCE_DIR}/crypto/falcon/PQClean/Falcon-1024/clean/*.c
)

set(FALCON_COMMON_SOURCES
    ${SOURCE_DIR}/crypto/falcon/PQClean/common/aes.c
    ${SOURCE_DIR}/crypto/falcon/PQClean/common/fips202.c
    ${SOURCE_DIR}/crypto/falcon/PQClean/common/sp800-185.c
    ${SOURCE_DIR}/crypto/falcon/PQClean/common/nistseedexpander.c
    ${SOURCE_DIR}/crypto/falcon/PQClean/common/randombytes.c
    ${SOURCE_DIR}/crypto/falcon/PQClean/common/sha2.c
)

file(GLOB FALCON_KECCAK4X_SOURCES
    ${SOURCE_DIR}/crypto/falcon/PQClean/common/keccak4x/*.c
)

set(FALCON_SOURCES
    ${FALCON_CLEAN_SOURCES}
    ${FALCON_COMMON_SOURCES}
    ${FALCON_KECCAK4X_SOURCES}
    ${FALCON_GLUE_SOURCES}
)

add_library(falcon STATIC ${FALCON_SOURCES})

target_include_directories(falcon PUBLIC
    ${SOURCE_DIR}/crypto/falcon/PQClean/Falcon-1024/clean
    ${SOURCE_DIR}/crypto/falcon/PQClean/common
    ${SOURCE_DIR}/crypto/falcon/PQClean/common/keccak2x
    ${SOURCE_DIR}/crypto/falcon/PQClean/common/keccak4x
)

set_source_files_properties(
    ${SOURCE_DIR}/crypto/falcon/PQClean/common/keccak4x/KeccakP-1600-times4-SIMD256.c
    PROPERTIES COMPILE_FLAGS "-mavx2 -msse4.1"
)

target_compile_options(falcon PUBLIC
    -DPQCLEAN_FALCON1024_CLEAN_NAMESPACE=PQCLEAN_FALCON1024_CLEAN_
    -DSHAKE256_NAMESPACE=PQCLEAN_FALCON1024_CLEAN_
)

# === Dilithium Static Library ===
file(GLOB DILITHIUM_SOURCES
    ${SOURCE_DIR}/crypto/dilithium/*.c
    ${SOURCE_DIR}/crypto/dilithium/ref/*.c
)

add_library(dilithium STATIC ${DILITHIUM_SOURCES})
target_include_directories(dilithium PUBLIC ${SOURCE_DIR}/crypto/dilithium/ref)

target_compile_options(dilithium PUBLIC
    -DPQCLEAN_DILITHIUM2_CLEAN_NAMESPACE=PQCLEAN_DILITHIUM2_CLEAN_
)

# --------------------------
# Build AlynCoin Core Library

# -- Dynamic link flags for protobuf, abseil, utf8_range and all static deps
execute_process(
    COMMAND pkg-config --static --libs protobuf
    OUTPUT_VARIABLE PROTOBUF_STATIC_LIBS_RAW
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
string(REPLACE "\n" " " PROTOBUF_STATIC_LIBS "${PROTOBUF_STATIC_LIBS_RAW}")

if(NOT SKIP_PROTOBUF_GEN)
    add_library(alyncoin_lib STATIC
        ${SOURCES}
        ${BLAKE3_SOURCES}
        ${PROTO_SRCS}
    )
else()
    add_library(alyncoin_lib STATIC
        ${SOURCES}
        ${BLAKE3_SOURCES}
    )
endif()

if(HAVE_MINIUPNPC)
    target_include_directories(alyncoin_lib PUBLIC ${MINIUPNPC_INCLUDE_DIR})
    target_compile_definitions(alyncoin_lib PUBLIC HAVE_MINIUPNPC MINIUPNPC_API_VERSION=17)
endif()

if(NOT SKIP_PROTOBUF_GEN)
    add_dependencies(alyncoin_lib protobuf_gen)
endif()
add_dependencies(alyncoin_lib winterfell_ffi)

set_source_files_properties(
    ${SOURCE_DIR}/blake3_sse2.c
    ${SOURCE_DIR}/blake3_sse41.c
    ${SOURCE_DIR}/blake3_avx2.c
    PROPERTIES COMPILE_FLAGS "${SIMD_FLAGS}"
)

target_link_libraries(alyncoin_lib
    PRIVATE
        OpenSSL::Crypto
        OpenSSL::SSL
        ${JSONCPP_LIBRARIES}
        pthread
        crypto
        m
        dl
        ${ROCKSDB_LIB}
        ${PROTOBUF_STATIC_LIBS} # <-- FULL protobuf + absl + utf8_range + etc.
        falcon
        dilithium
        ${SODIUM_LIB}
        ${SOURCE_DIR}/rust/target/release/libzk_winterfell.a
        resolv
)
if(HAVE_MINIUPNPC)
    target_link_libraries(alyncoin_lib PUBLIC ${UPNP_LIB})
endif()
if(NATPMP_LIBRARY)
    # expose natpmp to any target linking alyncoin_lib
    target_link_libraries(alyncoin_lib PUBLIC ${NATPMP_LIBRARY})
endif()

# --------------------------
# Main Executables
add_executable(alyncoin ${MAIN_SOURCE})
add_executable(alyncoin-cli
    ${SOURCE_DIR}/cli.cpp
    ${SOURCE_DIR}/cli/peer_blacklist_ui.cpp
    ${SOURCE_DIR}/zk/recursive_proof_helper.cpp
)
add_executable(peer_blacklist_cli ${SOURCE_DIR}/cli/peer_blacklist_cli.cpp)

add_dependencies(alyncoin winterfell_ffi)
add_dependencies(alyncoin-cli winterfell_ffi)
add_dependencies(peer_blacklist_cli winterfell_ffi)

target_compile_definitions(alyncoin PRIVATE ALYNCOIN_MAIN_PROCESS)
target_link_libraries(alyncoin alyncoin_lib pthread m dl)
target_link_libraries(alyncoin-cli alyncoin_lib pthread m dl)
target_link_libraries(peer_blacklist_cli
    alyncoin_lib
    ${JSONCPP_LIBRARIES}
    ${ROCKSDB_LIB}
    pthread
    m
    dl
)

# --------------------------
# Atomic Swap CLI
add_executable(swapcli
    ${SOURCE_DIR}/atomic_swaps/swapcli.cpp
    ${SOURCE_DIR}/atomic_swaps/swap_manager.cpp
    ${SOURCE_DIR}/atomic_swaps/rocksdb_swap_store.cpp
    ${SOURCE_DIR}/atomic_swaps/proto_utils.cpp
)
add_dependencies(swapcli winterfell_ffi)
target_link_libraries(swapcli
    alyncoin_lib
    ${JSONCPP_LIBRARIES}
    ${ROCKSDB_LIB}
    pthread
    crypto
    m
    dl
    falcon
    dilithium
    ${PROTOBUF_STATIC_LIBS}
    ${SOURCE_DIR}/rust/target/release/libzk_winterfell.a
)

add_executable(identitycli
    ${SOURCE_DIR}/identity/identitycli.cpp
    ${SOURCE_DIR}/identity/identity.cpp
    ${SOURCE_DIR}/identity/identity_store.cpp
    ${SOURCE_DIR}/identity/proto_utils.cpp
)
add_dependencies(identitycli winterfell_ffi)
target_link_libraries(identitycli
    alyncoin_lib
    ${JSONCPP_LIBRARIES}
    ${ROCKSDB_LIB}
    pthread
    crypto
    m
    dl
    falcon
    dilithium
    ${PROTOBUF_STATIC_LIBS}
)

add_executable(nftcli
    ${SOURCE_DIR}/nft/main.cpp
    ${SOURCE_DIR}/nft/nft_cli.cpp
    ${SOURCE_DIR}/nft/nft.cpp
    ${SOURCE_DIR}/nft/nft_storage.cpp
    ${SOURCE_DIR}/nft/crypto/aes_utils.cpp
)
add_dependencies(nftcli winterfell_ffi)
target_link_libraries(nftcli
    alyncoin_lib
    ${JSONCPP_LIBRARIES}
    ${ROCKSDB_LIB}
    pthread
    crypto
    m
    dl
    OpenSSL::Crypto
    falcon
    dilithium
    ${PROTOBUF_STATIC_LIBS}
)

# --------------------------
# Optional Test Executable
add_executable(blacklist_test ${SOURCE_DIR}/node/main_blacklist_test.cpp)
add_dependencies(blacklist_test winterfell_ffi)
target_link_libraries(blacklist_test
    alyncoin_lib
    ${JSONCPP_LIBRARIES}
    ${ROCKSDB_LIB}
    pthread
    m
    dl
)

# --------------------------
# Blockchain Explorer Executable
add_executable(explorer_server ${EXPLORER_SOURCES})
add_dependencies(explorer_server winterfell_ffi)
target_include_directories(explorer_server PRIVATE ${SOURCE_DIR}/explorer ${SOURCE_DIR}/deps/CrowInclude)
target_link_libraries(explorer_server
    alyncoin_lib
    ${JSONCPP_LIBRARIES}
    ${ROCKSDB_LIB}
    pthread
    ${PROTOBUF_STATIC_LIBS}
    m
    dl
)

# --------------------------
# Metrics Server Executable
add_executable(metrics_server ${METRICS_SOURCES})
add_dependencies(metrics_server winterfell_ffi)
target_include_directories(metrics_server PRIVATE ${SOURCE_DIR}/metrics ${SOURCE_DIR}/deps/CrowInclude)
target_link_libraries(metrics_server
    alyncoin_lib
    ${JSONCPP_LIBRARIES}
    pthread
    m
    dl
)

# Propagate UPnP library to all executables when available
if(HAVE_MINIUPNPC)
    foreach(tgt alyncoin alyncoin-cli peer_blacklist_cli swapcli identitycli nftcli blacklist_test explorer_server metrics_server)
        if(TARGET ${tgt})
            target_link_libraries(${tgt} ${UPNP_LIB})
        endif()
    endforeach()
endif()

# --------------------------
# Output Binaries Location
set_target_properties(alyncoin alyncoin-cli explorer_server metrics_server peer_blacklist_cli blacklist_test swapcli identitycli PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)

message(STATUS "AlynCoin Build Configured → Winterfell zk-STARK + Rollup + Falcon + Dilithium + Atomic Swap Integrated Successfully!")
