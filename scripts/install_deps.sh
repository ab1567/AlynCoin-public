#!/usr/bin/env bash
set -e

# Install core build dependencies
sudo apt update
sudo apt install -y dnsutils
sudo apt install -y \
  build-essential cmake pkg-config \
  libssl-dev libprotobuf-dev protobuf-compiler \
  libjsoncpp-dev libboost-all-dev \
  librocksdb-dev zlib1g-dev libbz2-dev \
  libsnappy-dev liblz4-dev libzstd-dev libsodium-dev \
  libasio-dev nlohmann-json3-dev \
  zip unzip git curl python3 python3-pip

# UPnP NAT traversal library
sudo apt install -y libminiupnpc-dev

