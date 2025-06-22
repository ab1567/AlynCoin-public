# AlynCoin

Privacy-focused cryptocurrency based on PoW.

## Generate RSA Keys

Generate RSA keys locally before building or running the software. The keys are
not tracked in version control:

```bash
mkdir -p keys
openssl genpkey -algorithm RSA -out keys/System_private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -in keys/System_private.pem -pubout -out keys/System_public.pem
```

## Build

Install the core development packages and networking tools using `apt`:

```bash
sudo apt update
sudo apt install -y dnsutils
sudo apt install -y \
  build-essential cmake pkg-config \
  libssl-dev libprotobuf-dev protobuf-compiler \
  libjsoncpp-dev libboost-all-dev \
  librocksdb-dev zlib1g-dev libbz2-dev \
  libsnappy-dev liblz4-dev libzstd-dev \
  libasio-dev nlohmann-json3-dev \
  zip unzip git curl python3 python3-pip

# UPnP NAT traversal library
sudo apt install -y libminiupnpc-dev
```

Compile the project using CMake:

```bash
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

Binaries such as `alyncoin` and `alyncoin-cli` will be placed in the `build`
directory.

## Run

Start a standalone node (network port 15671 by default) with:

```bash
./build/alyncoin --port 15671
```

The node exposes an HTTP RPC server on port `1567` by default. Use `--rpcport <port>`
if you need to change it and ensure it does not conflict with the peer network port.

Use `--dbpath <dir>` to specify a custom data directory or `--connect <ip>` to
connect to an existing peer.

`alyncoin-cli` can be used for command line transactions without running the
interactive node.

## GUI Wallet

The `application` directory contains a PyQt5 based wallet and miner GUI. After
building the node you can run the GUI locally:

```bash
# install Python dependencies
pip install -r application/requirements.txt

# in another terminal start the node
./build/alyncoin --port 15671

# launch the wallet GUI
python3 application/main.py
```

When running in a headless environment you can set `QT_QPA_PLATFORM=offscreen`
before launching the GUI.

## Usage

Running `./build/alyncoin` with no arguments opens an interactive menu. Options
include adding transactions, mining blocks, viewing balances and more.

Example: mine a single block for your address:

```bash
./build/alyncoin mineonce <yourAddress>
```

See subdirectory README files for modules such as the explorer, identity tools, and atomic swaps.

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
