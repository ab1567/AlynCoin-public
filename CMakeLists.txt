cmake_minimum_required(VERSION 3.10)
project(AlynCoin)

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
add_subdirectory(src/nft)
