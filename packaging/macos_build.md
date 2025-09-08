# macOS Build

## Prerequisites
- Xcode command line tools
- Homebrew

## Dependencies
```
brew install cmake openssl@3 protobuf rocksdb zstd
```

## Configure & Build
```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)
cmake --build build --config Release
```

Resulting binary: `build/alyncoin`
