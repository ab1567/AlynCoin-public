# Build Dependencies

To set up the AlynCoin build environment on Ubuntu, install the following packages.

```bash
# --- Install Core Build Dependencies ---
sudo apt update

sudo apt install -y dnsutils

sudo apt install -y \
  build-essential cmake pkg-config \
  libssl-dev libprotobuf-dev protobuf-compiler \
  libjsoncpp-dev libboost-all-dev \
  librocksdb-dev zlib1g-dev libbz2-dev \
  libsnappy-dev liblz4-dev libzstd-dev libsodium-dev \
  libasio-dev nlohmann-json3-dev \
  libspdlog-dev \
  libabsl-dev libnatpmp-dev \
  zip unzip git curl python3 python3-pip

# ---- Install UPnP NAT Traversal Library ----
sudo apt install -y libminiupnpc-dev
```

This installs all libraries required to compile AlynCoin. For parity with the macOS build, you should use **libprotoc 29.3**. Most Ubuntu repositories ship an older version, so follow [docs/install_protobuf_29_3.md](install_protobuf_29_3.md) to build it from source.
