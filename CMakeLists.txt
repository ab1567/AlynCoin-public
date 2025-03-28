cmake_minimum_required(VERSION 3.10)
project(AlynCoin)

# Set C++ Standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Output Directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Create generated directory BEFORE entering src/
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/generated)

# Add Subdirectory for src
add_subdirectory(src)
