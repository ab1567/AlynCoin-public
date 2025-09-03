cmake_minimum_required(VERSION 3.20)
project(AlynCoin)

# Force /MD(d)
set(CMAKE_POLICY_DEFAULT_CMP0091 NEW)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")

# ✅ Handle paths with spaces on Windows
if(WIN32)
    cmake_policy(SET CMP0053 NEW)
endif()

# ✅ Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ✅ Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# ✅ Ensure generated folder exists
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/generated)

# ✅ Add source directories
add_subdirectory(src)

# --- Install all binaries into a staging prefix ---
install(TARGETS
  alyncoin alyncoin-cli wallet_cli identitycli swapcli nftcli dao_cli
  explorer_server metrics_server peer_blacklist_cli
  RUNTIME DESTINATION bin
)

# --- CPack for packaging (macOS .dmg; Windows uses InnoSetup below) ---
set(CPACK_PACKAGE_NAME "AlynCoin")
set(CPACK_PACKAGE_VENDOR "AlynCoin")
set(CPACK_PACKAGE_VERSION "0.1.0")
set(CPACK_MONOLITHIC_INSTALL ON)
if(APPLE)
  set(CPACK_GENERATOR "DragNDrop")
endif()
include(CPack)
