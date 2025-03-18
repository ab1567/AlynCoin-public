cmake_minimum_required(VERSION 3.10)
project(alyncoin)

# Set C++ Standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Detect CPU Architecture
include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)

message(STATUS "🔍 Detecting CPU Architecture...")

set(ARCHITECTURE "Generic")
set(SIMD_FLAGS "")

if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
    set(ARCHITECTURE "x86_64")
    message(STATUS "✅ Compiling for x86_64 (BLAKE3 SSE4.1 & AVX2 optimizations enabled)")
    add_compile_definitions(USE_SSE4_1 USE_AVX2)
    set(SIMD_FLAGS "-msse4.1 -mavx2")

    # Disable AVX-512 if detected
    check_cxx_compiler_flag("-mavx512f" HAS_AVX512)
    if(HAS_AVX512)
        message(WARNING "⚠️  AVX-512 detected but will be DISABLED to prevent linker errors.")
        set(AVX512_DISABLED TRUE)
    endif()

elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
    set(ARCHITECTURE "ARM64")
    message(STATUS "✅ Compiling for ARM64 (Portable BLAKE3 implementation)")
    add_compile_definitions(USE_ARM_NEON)

elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "arm")
    set(ARCHITECTURE "ARM")
    message(STATUS "✅ Compiling for ARM (32-bit) - Using Portable BLAKE3 Implementation")
    add_compile_definitions(USE_ARM_NEON)

else()
    message(WARNING "⚠️  Unknown architecture detected - Using Portable BLAKE3 implementation")
endif()

# **Ensure Source Files Exist**
set(SOURCE_DIR ${CMAKE_SOURCE_DIR}/src)
file(GLOB SOURCES
    ${SOURCE_DIR}/block.cpp
    ${SOURCE_DIR}/blockchain.cpp
    ${SOURCE_DIR}/syncing.cpp
    ${SOURCE_DIR}/transaction.cpp
    ${SOURCE_DIR}/network.cpp
    ${SOURCE_DIR}/crypto_utils.cpp
    ${SOURCE_DIR}/miner.cpp
    ${SOURCE_DIR}/wallet.cpp
    ${SOURCE_DIR}/keccak.cpp
    ${SOURCE_DIR}/key_paths.cpp   # ✅ Add key_paths.cpp for global functions
)

set(MAIN_SOURCE ${SOURCE_DIR}/main.cpp)  # ✅ Separate main.cpp
set(CLI_SOURCE ${SOURCE_DIR}/cli.cpp)    # ✅ Separate cli.cpp

# **BLAKE3 Source Files**
set(BLAKE3_SOURCES
    ${SOURCE_DIR}/blake3.c
    ${SOURCE_DIR}/blake3_dispatch.c
    ${SOURCE_DIR}/blake3_portable.c
    ${SOURCE_DIR}/blake3_sse2.c
    ${SOURCE_DIR}/blake3_sse41.c
    ${SOURCE_DIR}/blake3_avx2.c
)

# **Disable AVX-512 if Needed**
if(AVX512_DISABLED)
    add_compile_definitions(BLAKE3_NO_AVX512)
    set_source_files_properties(${SOURCE_DIR}/blake3_dispatch.c PROPERTIES COMPILE_DEFINITIONS "BLAKE3_NO_AVX512")
    message(STATUS "🚫 Removing AVX-512 files to prevent linker errors.")
endif()

# **Ensure Generated Directory Exists**
set(GENERATED_DIR ${CMAKE_BINARY_DIR}/generated)
file(MAKE_DIRECTORY ${GENERATED_DIR})

# **Include Directories**
include_directories(
    ${SOURCE_DIR}
    ${GENERATED_DIR}  # ✅ Include Protobuf-generated headers
    /usr/include/jsoncpp
    /usr/include/rocksdb
)

# **Library Dependencies**
find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(JSONCPP jsoncpp)
pkg_check_modules(ROCKSDB REQUIRED rocksdb)
find_package(Protobuf REQUIRED)

# **Protobuf Files**
set(PROTO_SRCS
    ${GENERATED_DIR}/sync_protos.pb.cc
    ${GENERATED_DIR}/block_protos.pb.cc
    ${GENERATED_DIR}/blockchain_protos.pb.cc  # ✅ Newly added blockchain_protos
    ${GENERATED_DIR}/crypto_protos.pb.cc
    ${GENERATED_DIR}/transaction_protos.pb.cc
    ${GENERATED_DIR}/main_protos.pb.cc
)

set(PROTO_HEADERS
    ${GENERATED_DIR}/sync_protos.pb.h
    ${GENERATED_DIR}/block_protos.pb.h
    ${GENERATED_DIR}/blockchain_protos.pb.h  # ✅ Newly added blockchain_protos
    ${GENERATED_DIR}/crypto_protos.pb.h
    ${GENERATED_DIR}/transaction_protos.pb.h
    ${GENERATED_DIR}/main_protos.pb.h
)

# **Generate Protobuf Headers & Sources**
add_custom_command(
    OUTPUT ${PROTO_HEADERS} ${PROTO_SRCS}
    COMMAND ${Protobuf_PROTOC_EXECUTABLE} --proto_path=${SOURCE_DIR}/proto
            --cpp_out=${GENERATED_DIR}
            ${SOURCE_DIR}/proto/sync_protos.proto
            ${SOURCE_DIR}/proto/block_protos.proto
            ${SOURCE_DIR}/proto/blockchain_protos.proto  # ✅ Ensure blockchain Protobuf is included
            ${SOURCE_DIR}/proto/crypto_protos.proto
            ${SOURCE_DIR}/proto/transaction_protos.proto
            ${SOURCE_DIR}/proto/main_protos.proto
    DEPENDS ${SOURCE_DIR}/proto/sync_protos.proto
            ${SOURCE_DIR}/proto/block_protos.proto
            ${SOURCE_DIR}/proto/blockchain_protos.proto  # ✅ Ensure blockchain Protobuf dependency
            ${SOURCE_DIR}/proto/crypto_protos.proto
            ${SOURCE_DIR}/proto/transaction_protos.proto
            ${SOURCE_DIR}/proto/main_protos.proto
    COMMENT "🚀 Generating Protobuf files..."
)

# **Build Alyncoin Library**
add_library(alyncoin_lib STATIC ${SOURCES} ${BLAKE3_SOURCES} ${PROTO_SRCS})

# **Apply SIMD Optimizations**
set_source_files_properties(${SOURCE_DIR}/blake3_sse2.c ${SOURCE_DIR}/blake3_sse41.c ${SOURCE_DIR}/blake3_avx2.c PROPERTIES COMPILE_FLAGS "${SIMD_FLAGS}")

# **Linking External Libraries**
target_link_libraries(alyncoin_lib
    OpenSSL::Crypto
    ${JSONCPP_LIBRARIES}
    pthread
    crypto
    ${ROCKSDB_LIBRARIES}
    ${Protobuf_LIBRARIES}
)

# **💡 Fix Binary Placement: Move Executables to Build Root**
add_executable(alyncoin ${MAIN_SOURCE})  # ✅ Only main.cpp for blockchain
add_executable(alyncoin-cli ${CLI_SOURCE})  # ✅ Only cli.cpp for CLI tool

set_target_properties(alyncoin alyncoin-cli PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)

target_link_libraries(alyncoin alyncoin_lib)
target_link_libraries(alyncoin-cli alyncoin_lib)

message(STATUS "✅ AlynCoin Build Configured Successfully!")
