# Build Dependencies

To set up the AlynCoin build environment on Ubuntu, install the following packages.

```bash
sudo apt update && sudo apt install -y \
  dnsutils ca-certificates curl git zip unzip python3 python3-pip \
  build-essential cmake ninja-build pkg-config \
  libssl-dev libprotobuf-dev protobuf-compiler \
  libjsoncpp-dev libboost-all-dev \
  librocksdb-dev zlib1g-dev libbz2-dev libsnappy-dev liblz4-dev libzstd-dev \
  libsodium-dev libasio-dev nlohmann-json3-dev \
  libminiupnpc-dev libnatpmp-dev \
  libabsl-dev \
  rustc cargo
```

This installs every package required to compile AlynCoin on Ubuntu, matching the dependency set used in CI. For parity with the macOS build, you should use **libprotoc 29.3**. Most Ubuntu repositories ship an older version, so follow [docs/install_protobuf_29_3.md](install_protobuf_29_3.md) to build it from source.

## Build and smoke-test

After installing the dependencies, configure and compile the project (the Ninja generator offers the fastest incremental builds):

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

To run the compiled smoke tests (if enabled in your checkout), execute:

```bash
ctest --test-dir build --output-on-failure
```
