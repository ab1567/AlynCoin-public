cmake_minimum_required(VERSION 3.20)
project(alyncoin LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ---- Windows toolchain / CRT -------------------------------------------------
if (WIN32)
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
  add_definitions(-DWIN32_LEAN_AND_MEAN -DNOMINMAX -DMINIUPNP_STATICLIB -D_WIN32_WINNT=0x0A00 -D_CRT_SECURE_NO_WARNINGS)
endif()

# ---- CPU / SIMD flags --------------------------------------------------------
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
  add_compile_definitions(USE_ARM_NEON)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "arm")
  set(ARCHITECTURE "ARM")
  add_compile_definitions(USE_ARM_NEON)
else()
  message(WARNING "Unknown architecture detected - using portable BLAKE3.")
endif()

# ---- Paths -------------------------------------------------------------------
set(SOURCE_DIR ${CMAKE_SOURCE_DIR}/src)
set(GENERATED_DIR ${CMAKE_BINARY_DIR}/generated)
file(MAKE_DIRECTORY ${GENERATED_DIR})

# ---- Sources -----------------------------------------------------------------
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
  ${SOURCE_DIR}/self_healing/health_monitor.cpp
  ${SOURCE_DIR}/self_healing/sync_recovery.cpp
  ${SOURCE_DIR}/self_healing/self_healing_node.cpp
  ${SOURCE_DIR}/utils/logger.cpp
  ${SOURCE_DIR}/identity/identity.cpp
  ${SOURCE_DIR}/identity/identity_store.cpp
  ${SOURCE_DIR}/identity/proto_utils.cpp
  ${SOURCE_DIR}/db/rocksdb_wrapper.cpp
  ${SOURCE_DIR}/db/db_instance.cpp
  ${SOURCE_DIR}/db/db_writer.cpp
  ${SOURCE_DIR}/nft/nft.cpp
  ${SOURCE_DIR}/nft/nft_storage.cpp
  ${SOURCE_DIR}/nft/crypto/aes_utils.cpp
  ${SOURCE_DIR}/nft/nft_utils.cpp
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
file(GLOB METRICS_SOURCES  ${SOURCE_DIR}/metrics/*.cpp)
file(GLOB RPC_SOURCES      ${SOURCE_DIR}/rpc/*.cpp)
list(APPEND SOURCES ${RPC_SOURCES})

set(MAIN_SOURCE ${SOURCE_DIR}/main.cpp)

# ---- BLAKE3 ------------------------------------------------------------------
# The BLAKE3 implementation is provided by the Rust Winterfell library.
# Avoid building the duplicate C sources here to prevent linker conflicts and
# ensure consistent builds across all platforms (Linux, macOS, Windows).
# Only the header is needed for external consumers.

# ---- Includes ----------------------------------------------------------------
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
if (NOT WIN32)
  include_directories(/usr/include/jsoncpp /usr/include/rocksdb)
endif()
if (WIN32 AND DEFINED ENV{VCPKG_ROOT})
  include_directories("$ENV{VCPKG_ROOT}/installed/x64-windows-static/include")
endif()

# ---- Dependencies ------------------------------------------------------------
# Use vcpkg-provided config packages
find_package(OpenSSL REQUIRED COMPONENTS Crypto SSL)
message(STATUS "OpenSSL found: ${OPENSSL_VERSION} (targets OpenSSL::Crypto / OpenSSL::SSL)")

# Header-only multiprecision is exposed via imported targets in modern Boost
find_package(Boost REQUIRED COMPONENTS headers)
if (WIN32)
  find_package(protobuf CONFIG REQUIRED)
  # Make protoc path available to the codegen rule
  set(Protobuf_PROTOC_EXECUTABLE $<TARGET_FILE:protobuf::protoc>)
  find_package(jsoncpp CONFIG REQUIRED)
  find_package(RocksDB CONFIG REQUIRED)
  find_package(unofficial-sodium CONFIG REQUIRED)
  find_package(lz4 CONFIG REQUIRED)
  find_package(zstd CONFIG REQUIRED)
  find_package(miniupnpc CONFIG REQUIRED)
  set(JSONCPP_LIBRARIES JsonCpp::JsonCpp)
  set(ROCKSDB_LIB       RocksDB::rocksdb)
  set(SODIUM_LIB        unofficial-sodium::sodium)
  set(UPNP_LIB          miniupnpc::miniupnpc)
else()
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(JSONCPP jsoncpp)
  if(JSONCPP_FOUND)
    message(STATUS "Found JsonCpp: ${JSONCPP_VERSION}")
    include_directories(${JSONCPP_INCLUDE_DIRS})
    link_directories(${JSONCPP_LIBRARY_DIRS})
  else()
    message(FATAL_ERROR "JsonCpp not found, please install it (e.g. via brew install jsoncpp)")
  endif()
  find_package(Protobuf REQUIRED)
  find_package(absl REQUIRED)
  find_library(SODIUM_LIB sodium REQUIRED)
  find_path(SODIUM_INCLUDE_DIR sodium.h)
  include_directories(${SODIUM_INCLUDE_DIR})
  find_library(ROCKSDB_LIB rocksdb REQUIRED)
  find_path(ROCKSDB_INCLUDE_DIR rocksdb/db.h)
  include_directories(${ROCKSDB_INCLUDE_DIR})
endif()

# ---- UPnP --------------------------------------------------------------------
if (WIN32)
  set(HAVE_MINIUPNPC TRUE)  # using vcpkg target
else()
  set(HAVE_MINIUPNPC TRUE)
  add_subdirectory(${SOURCE_DIR}/deps/miniupnpc EXCLUDE_FROM_ALL)
  set(UPNP_LIB miniupnpc)
endif()

find_path(NATPMP_INCLUDE_DIR natpmp.h)
find_library(NATPMP_LIBRARY NAMES natpmp libnatpmp)
if(NATPMP_INCLUDE_DIR AND NATPMP_LIBRARY)
  message(STATUS "libnatpmp found: ${NATPMP_LIBRARY}")
  add_definitions(-DHAVE_LIBNATPMP)
  include_directories(${NATPMP_INCLUDE_DIR})
else()
  message(WARNING "libnatpmp not found, NAT-PMP will be disabled.")
endif()

# ---- Protobuf codegen --------------------------------------------------------
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

# ---- Rust FFI ----------------------------------------------------------------
if (WIN32)
  add_custom_target(winterfell_ffi ALL
    COMMAND cargo build --release --target x86_64-pc-windows-msvc
    WORKING_DIRECTORY ${SOURCE_DIR}/rust
    COMMENT "Building Winterfell zk-STARK Rust FFI (MSVC)..."
  )
else()
  add_custom_target(winterfell_ffi ALL
    COMMAND cargo build --release
    WORKING_DIRECTORY ${SOURCE_DIR}/rust
    COMMENT "Building Winterfell zk-STARK Rust FFI..."
  )
endif()

if (WIN32)
  set(WINTERFELL_LIB "${SOURCE_DIR}/rust/target/x86_64-pc-windows-msvc/release/zk_winterfell.lib")
else()
  set(WINTERFELL_LIB "${SOURCE_DIR}/rust/target/release/libzk_winterfell.a")
endif()

# ---- Platform libs -----------------------------------------------------------
if (WIN32)
  set(PLAT_LIBS ws2_32 iphlpapi bcrypt crypt32)
else()
  set(PLAT_LIBS pthread m dl resolv)
endif()

# Ensure JsonCpp is linked on all platforms
list(APPEND PLAT_LIBS ${JSONCPP_LIBRARIES})

# ---- Falcon (C) --------------------------------------------------------------
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
if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(arm64|aarch64)$" OR CMAKE_OSX_ARCHITECTURES MATCHES "arm64")
  message(STATUS "ARM64 architecture detected – disabling AVX2/SSE for Falcon")
  add_definitions(-DPQCLEAN_NO_SIMD)
else()
  file(GLOB FALCON_KECCAK4X_SOURCES
    ${SOURCE_DIR}/crypto/falcon/PQClean/common/keccak4x/*.c
  )
endif()
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
)
if(FALCON_KECCAK4X_SOURCES)
  target_include_directories(falcon PUBLIC
    ${SOURCE_DIR}/crypto/falcon/PQClean/common/keccak4x
  )
endif()
target_compile_definitions(falcon PUBLIC
  PQCLEAN_FALCON1024_CLEAN_NAMESPACE=PQCLEAN_FALCON1024_CLEAN_
  SHAKE256_NAMESPACE=PQCLEAN_FALCON1024_CLEAN_
)
if (NOT MSVC AND FALCON_KECCAK4X_SOURCES)
  set_source_files_properties(
    ${SOURCE_DIR}/crypto/falcon/PQClean/common/keccak4x/KeccakP-1600-times4-SIMD256.c
    PROPERTIES COMPILE_FLAGS "-mavx2 -msse4.1"
  )
endif()

# ---- Dilithium (C) -----------------------------------------------------------
file(GLOB DILITHIUM_SOURCES
  ${SOURCE_DIR}/crypto/dilithium/*.c
  ${SOURCE_DIR}/crypto/dilithium/ref/*.c
)
list(FILTER DILITHIUM_SOURCES EXCLUDE REGEX "randombytes\.c$")
add_library(dilithium STATIC ${DILITHIUM_SOURCES})
target_include_directories(dilithium PUBLIC ${SOURCE_DIR}/crypto/dilithium/ref)
target_compile_definitions(dilithium PUBLIC
  PQCLEAN_DILITHIUM2_CLEAN_NAMESPACE=PQCLEAN_DILITHIUM2_CLEAN_
)
target_link_libraries(dilithium PUBLIC ${SODIUM_LIB})

# ---- Core static lib ---------------------------------------------------------
  if(NOT SKIP_PROTOBUF_GEN)
    add_library(alyncoin_lib STATIC ${SOURCES} ${PROTO_SRCS})
  else()
    add_library(alyncoin_lib STATIC ${SOURCES})
  endif()

if(HAVE_MINIUPNPC)
  target_compile_definitions(alyncoin_lib PUBLIC HAVE_MINIUPNPC MINIUPNPC_API_VERSION=17)
endif()
if(NOT SKIP_PROTOBUF_GEN)
  add_dependencies(alyncoin_lib protobuf_gen)
endif()
add_dependencies(alyncoin_lib winterfell_ffi)

if (NOT MSVC)
  set_source_files_properties(
    ${SOURCE_DIR}/blake3_sse2.c
    ${SOURCE_DIR}/blake3_sse41.c
    ${SOURCE_DIR}/blake3_avx2.c
    PROPERTIES COMPILE_FLAGS "${SIMD_FLAGS}"
  )
endif()

if (WIN32)
  set(PROTOBUF_LINK protobuf::libprotobuf)
else()
  execute_process(
    COMMAND pkg-config --static --libs protobuf
    OUTPUT_VARIABLE PROTOBUF_STATIC_LIBS_RAW
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )
  string(REPLACE "\n" " " PROTOBUF_STATIC_LIBS "${PROTOBUF_STATIC_LIBS_RAW}")
  set(PROTOBUF_LINK ${PROTOBUF_STATIC_LIBS})
endif()

target_link_libraries(alyncoin_lib
  PRIVATE
    OpenSSL::Crypto
    OpenSSL::SSL
    ${JSONCPP_LIBRARIES}
    ${ROCKSDB_LIB}
    ${PROTOBUF_LINK}
    falcon
    dilithium
    ${SODIUM_LIB}
    ${WINTERFELL_LIB}
    ${PLAT_LIBS}
)
if (TARGET Boost::headers)
  target_link_libraries(alyncoin_lib PRIVATE Boost::headers)
else()
  include_directories(${Boost_INCLUDE_DIRS})
endif()
if (WIN32)
  target_link_libraries(alyncoin_lib PRIVATE lz4::lz4 zstd::libzstd)
endif()

if(HAVE_MINIUPNPC)
  target_link_libraries(alyncoin_lib PUBLIC ${UPNP_LIB})
endif()
if(NATPMP_LIBRARY)
  target_link_libraries(alyncoin_lib PUBLIC ${NATPMP_LIBRARY})
endif()

# ---- Executables -------------------------------------------------------------
add_executable(alyncoin ${MAIN_SOURCE})
add_executable(alyncoin-cli
  ${SOURCE_DIR}/cli.cpp
  ${SOURCE_DIR}/cli/peer_blacklist_ui.cpp
  ${SOURCE_DIR}/zk/recursive_proof_helper.cpp
)
add_executable(peer_blacklist_cli ${SOURCE_DIR}/cli/peer_blacklist_cli.cpp)

add_executable(wallet_cli ${SOURCE_DIR}/wallet_cli.cpp)
add_executable(dao_cli    ${SOURCE_DIR}/governance/cli/dao_cli.cpp)
add_executable(devfund_cli ${SOURCE_DIR}/governance/cli/devfund_cli.cpp)

add_dependencies(alyncoin winterfell_ffi)
add_dependencies(alyncoin-cli winterfell_ffi)
add_dependencies(peer_blacklist_cli winterfell_ffi)
add_dependencies(wallet_cli winterfell_ffi)
add_dependencies(dao_cli winterfell_ffi)
add_dependencies(devfund_cli winterfell_ffi)

target_compile_definitions(alyncoin PRIVATE ALYNCOIN_MAIN_PROCESS)
target_link_libraries(alyncoin        PRIVATE alyncoin_lib ${PLAT_LIBS})
target_link_libraries(alyncoin-cli    PRIVATE alyncoin_lib ${PLAT_LIBS})
target_link_libraries(peer_blacklist_cli PRIVATE alyncoin_lib ${PLAT_LIBS})
target_link_libraries(wallet_cli PRIVATE alyncoin_lib ${PLAT_LIBS})
target_link_libraries(dao_cli    PRIVATE alyncoin_lib ${PLAT_LIBS})
target_link_libraries(devfund_cli PRIVATE alyncoin_lib ${PLAT_LIBS})

# Atomic Swap CLI
add_executable(swapcli
  ${SOURCE_DIR}/atomic_swaps/swapcli.cpp
  ${SOURCE_DIR}/atomic_swaps/swap_manager.cpp
  ${SOURCE_DIR}/atomic_swaps/rocksdb_swap_store.cpp
  ${SOURCE_DIR}/atomic_swaps/proto_utils.cpp
)
add_dependencies(swapcli winterfell_ffi)
target_link_libraries(swapcli
  PRIVATE
    alyncoin_lib
    ${JSONCPP_LIBRARIES}
    ${ROCKSDB_LIB}
    falcon
    dilithium
    ${PROTOBUF_LINK}
    ${PLAT_LIBS}
)

# Identity CLI
add_executable(identitycli
  ${SOURCE_DIR}/identity/identitycli.cpp
  ${SOURCE_DIR}/identity/identity.cpp
  ${SOURCE_DIR}/identity/identity_store.cpp
  ${SOURCE_DIR}/identity/proto_utils.cpp
)
add_dependencies(identitycli winterfell_ffi)
target_link_libraries(identitycli
  PRIVATE
    alyncoin_lib
    ${JSONCPP_LIBRARIES}
    ${ROCKSDB_LIB}
    falcon
    dilithium
    ${PROTOBUF_LINK}
    ${PLAT_LIBS}
)

# NFT CLI
add_executable(nftcli
  ${SOURCE_DIR}/nft/main.cpp
  ${SOURCE_DIR}/nft/nft_cli.cpp
  ${SOURCE_DIR}/nft/nft.cpp
  ${SOURCE_DIR}/nft/nft_storage.cpp
  ${SOURCE_DIR}/nft/crypto/aes_utils.cpp
)
add_dependencies(nftcli winterfell_ffi)
target_link_libraries(nftcli
  PRIVATE
    alyncoin_lib
    ${JSONCPP_LIBRARIES}
    ${ROCKSDB_LIB}
    OpenSSL::Crypto
    falcon
    dilithium
    ${PROTOBUF_LINK}
    ${PLAT_LIBS}
)

# Optional test
add_executable(blacklist_test ${SOURCE_DIR}/node/main_blacklist_test.cpp)
add_dependencies(blacklist_test winterfell_ffi)
target_link_libraries(blacklist_test  PRIVATE alyncoin_lib ${JSONCPP_LIBRARIES} ${ROCKSDB_LIB} ${PLAT_LIBS})

# Explorer
add_executable(explorer_server ${EXPLORER_SOURCES})
add_dependencies(explorer_server winterfell_ffi)
target_include_directories(explorer_server PRIVATE ${SOURCE_DIR}/explorer ${SOURCE_DIR}/deps/CrowInclude)
target_link_libraries(explorer_server PRIVATE alyncoin_lib ${JSONCPP_LIBRARIES} ${ROCKSDB_LIB} ${PROTOBUF_LINK} ${PLAT_LIBS})

# Metrics
add_executable(metrics_server ${METRICS_SOURCES})
add_dependencies(metrics_server winterfell_ffi)
target_include_directories(metrics_server PRIVATE ${SOURCE_DIR}/metrics ${SOURCE_DIR}/deps/CrowInclude)
target_link_libraries(metrics_server  PRIVATE alyncoin_lib ${JSONCPP_LIBRARIES} ${PLAT_LIBS})

# ---- UPnP propagation --------------------------------------------------------
if(HAVE_MINIUPNPC)
  foreach(tgt alyncoin alyncoin-cli peer_blacklist_cli swapcli identitycli nftcli blacklist_test explorer_server metrics_server wallet_cli dao_cli devfund_cli)
    if(TARGET ${tgt})
      target_link_libraries(${tgt} PRIVATE ${UPNP_LIB})
    endif()
  endforeach()
endif()

# Link Windows executables against ntdll for native system calls
if(MSVC)
  foreach(tgt alyncoin alyncoin-cli peer_blacklist_cli swapcli identitycli nftcli blacklist_test explorer_server metrics_server wallet_cli dao_cli devfund_cli)
    if(TARGET ${tgt})
      target_link_libraries(${tgt} PRIVATE ntdll)
    endif()
  endforeach()
endif()

# ---- Output dirs -------------------------------------------------------------
set_target_properties(alyncoin alyncoin-cli explorer_server metrics_server peer_blacklist_cli blacklist_test swapcli identitycli nftcli wallet_cli dao_cli devfund_cli
  PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)

message(STATUS "AlynCoin configured: static deps and cross-platform build ready.")
