option(WITH_FALCON "Build with Falcon support" ON)
option(WITH_DILITHIUM "Build with Dilithium support" ON)

if(NOT WITH_FALCON)
    add_definitions(-DWITHOUT_FALCON)
endif()
if(NOT WITH_DILITHIUM)
    add_definitions(-DWITHOUT_DILITHIUM)
endif()
