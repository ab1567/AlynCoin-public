cmake_minimum_required(VERSION 3.10)
project(AlynCoin)

# ✅ Handle paths with spaces on Windows
if(WIN32)
    cmake_policy(SET CMP0053 NEW)
endif()

# ✅ Set C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ✅ Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# ✅ Ensure generated folder exists
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/generated)

# ✅ Add source directories
add_subdirectory(src)
