FROM ubuntu:22.04

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    librocksdb-dev \
    libjsoncpp-dev \
    libboost-all-dev \
    wget \
    protobuf-compiler \
    libprotobuf-dev \
    libssl-dev \
    pkg-config \
    curl

# Install Rust (for Winterfell FFI)
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Set work directory
WORKDIR /AlynCoin/src

# Copy source code
COPY . .

# Build steps
RUN mkdir build && cd build && cmake .. && make

# Expose Explorer ports
EXPOSE 8080

# Command to run explorer
CMD ["./build/explorer_server"]
