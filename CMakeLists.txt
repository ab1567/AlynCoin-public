cmake_minimum_required(VERSION 3.20)
project(AlynCoin)

if(MSVC)
  set(CMAKE_POLICY_DEFAULT_CMP0091 NEW)
  # Use static CRT for all configurations (/MT, /MTd)
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
  foreach(flag_var
    CMAKE_C_FLAGS CMAKE_C_FLAGS_DEBUG CMAKE_C_FLAGS_RELEASE
    CMAKE_C_FLAGS_RELWITHDEBINFO CMAKE_C_FLAGS_MINSIZEREL
    CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_DEBUG CMAKE_CXX_FLAGS_RELEASE
    CMAKE_CXX_FLAGS_RELWITHDEBINFO CMAKE_CXX_FLAGS_MINSIZEREL)
    if(DEFINED ${flag_var})
      string(REPLACE "/MD" "/MT" ${flag_var} "${${flag_var}}")
      set(${flag_var} "${${flag_var}}" CACHE STRING "" FORCE)
    endif()
  endforeach()
endif()

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

# --- Install all runtime targets into bin/ ---
install(TARGETS
  alyncoin alyncoin-cli wallet_cli identitycli swapcli nftcli dao_cli
  explorer_server metrics_server peer_blacklist_cli devfund_cli blacklist_test
  RUNTIME DESTINATION bin
)

# (optional) CPack for macOS DMG later
set(CPACK_PACKAGE_NAME "AlynCoin")
set(CPACK_PACKAGE_VERSION "0.1.0")
include(CPack)
