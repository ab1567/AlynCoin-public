# Windows Build

## Prerequisites
- Visual Studio 2022 with C++ Desktop workload
- CMake and Ninja
- vcpkg package manager

## Dependencies
```
vcpkg install openssl:x64-windows protobuf:x64-windows rocksdb[zstd]:x64-windows zstd:x64-windows
```

## Configure & Build
```
cmake -S . -B build -G "Ninja" -DCMAKE_TOOLCHAIN_FILE=C:/path/vcpkg/scripts/buildsystems/vcpkg.cmake -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

Resulting binary: `build\alyncoin.exe`
