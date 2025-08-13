cmake_minimum_required(VERSION 3.10)
project(AlynCoin)

# ✅ Handle paths with spaces on Windows
if(WIN32)
    cmake_policy(SET CMP0053 NEW)
endif()

# ✅ Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ✅ Use the dynamic MSVC runtime (/MD or /MDd)
if (MSVC)
  if (CMAKE_VERSION VERSION_GREATER_EQUAL "3.15")
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
  else()
    foreach(flag_var CMAKE_C_FLAGS CMAKE_C_FLAGS_DEBUG CMAKE_C_FLAGS_RELEASE
                    CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_DEBUG CMAKE_CXX_FLAGS_RELEASE)
      if (DEFINED ${flag_var})
        string(REPLACE "/MT" "/MD" ${flag_var} "${${flag_var}}")
        string(REPLACE "/MTd" "/MDd" ${flag_var} "${${flag_var}}")
        set(${flag_var} "${${flag_var}}" CACHE STRING "" FORCE)
      endif()
    endforeach()
  endif()
endif()

# ✅ Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# ✅ Ensure generated folder exists
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/generated)

# ✅ Add source directories
add_subdirectory(src)
