# AlynCoin

AlynCoin is a quantum-resistant Layer-1 blockchain. It combines BLAKE3 and
Keccak proof-of-work mining with advanced zk-STARK proofs and supports the
Falcon and Dilithium digital signature schemes. The project targets future
quantum threats while retaining the familiarity of a traditional PoW chain.

## Key Features

* **Quantum-secure signatures** using both Falcon and Dilithium
* **zk-STARK proofs** with recursive rollups for scalability
* **Self-healing nodes** that automatically resynchronize
* **DAO governance** powered by zero-knowledge proofs
* **Atomic swaps and NFT support**
* **Hybrid PoW algorithm** blending BLAKE3 and Keccak

## Tokenomics

AlynCoin has a fixed cap of **100 million ALYN** tokens. The genesis block
includes a premine of **10 million ALYN** distributed as follows:

| Allocation           | Amount (ALYN) |
|----------------------|---------------|
| Airdrops             | 1,000,000     |
| Liquidity            | 1,000,000     |
| Investors            | 3,000,000     |
| Development          | 2,000,000     |
| Exchange Listings    | 1,000,000     |
| Team/Founder         | 2,000,000     |

Block rewards decline as circulating supply approaches the cap. A portion of
transaction fees is burned while another portion funds ongoing development via
the DAO treasury. The team allocation is locked for one year and vests
linearly over the following three years.

### Difficulty and Emission

* Difficulty adjusts every block using a logistic floor that gradually rises
  from 5 to 40 as total supply reaches 100&nbsp;M.
* Block rewards start at 25 ALYN and decay by about 0.09&nbsp;% per block with
  a permanent 0.25 ALYN tail emission to incentivize miners long term.

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
  libsnappy-dev liblz4-dev libzstd-dev libsodium-dev \
  libasio-dev nlohmann-json3-dev \
  libspdlog-dev \
  zip unzip git curl python3 python3-pip

# UPnP NAT traversal library
sudo apt install -y libminiupnpc-dev
```

To install all of these packages automatically, run:

```bash
./scripts/install_deps.sh
```

Compile the project using CMake:

```bash
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

Run the basic unit tests to verify the build:

```bash
make blacklist_test
./blacklist_test
```

Trace-level lock diagnostics are disabled by default. If you need detailed
mutex tracing for debugging, pass `-DENABLE_LOCK_TRACING=ON` to CMake when
configuring the build.

Binaries such as `alyncoin` and `alyncoin-cli` will be placed in the `build`
directory.

## Networking updates

Version 4 of the network frame protocol introduces temporary-ban decay
support. Nodes now advertise a `ban_decay_v1` capability in their handshake
messages. When connections are denied due to the /24 prefix cap or when a
24-hour ban expires, informative log messages are written so operators can
easily trace peer reputation changes.

Peers accrue a small `mis_score` when they exceed reasonable bandwidth
limits. The score decays every minute and only triggers a ban once it reaches
100 points. Height responses with less cumulative work than the local node
also increase `mis_score`, helping catch dishonest peers without penalizing
legitimate traffic.

## Run

Start a standalone node (network port 15671 by default) with:

```bash
./build/alyncoin --port 15671
```

The node exposes an HTTP RPC server on port `1567` by default. Use `--rpcport <port>`
if you need to change it and ensure it does not conflict with the peer network port.

Use `--dbpath <dir>` to specify a custom data directory or `--connect <ip>` to
connect to an existing peer. Peer ban duration defaults to five minutes but can
be adjusted with `--banminutes <m>` or by editing `config.ini`.

## Join the Network

Peers can be listed in `peers.txt` or specified on the command line. To join the
public test network, run:

```bash
./build/alyncoin --connect <peer_ip>
```

The default RPC port is `1567` and the peer port is `15671`.

### Automatic network sync

The node shares its current block height with peers whenever a new block is
mined or received. Peers compare heights and request any missing tail blocks or
snapshots without needing a restart. If a snapshot message contains exactly one
block at the next height, the node treats it as a live tail push and appends the
block immediately. Periodic health checks also probe peers to ensure connections
stay alive and synchronize in the background.
Nodes will now request up to 100 missing blocks directly (see the
`TAIL_SYNC_THRESHOLD` constant) before falling back to snapshot or
epoch-based syncing. This speeds up recovery from short forks and reduces
network load.

### Permission denied when starting the node

`alyncoind` stores its RocksDB files under `~/.alyncoin/blockchain_db` by
default. The GUI launcher now creates this directory automatically if it is
missing.  Should directory creation fail, the startup log will report the
problem so you can adjust permissions.

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

The wallet stores keys in `~/.alyncoin`. Ensure this directory is writable
by your user. If the GUI fails to create it automatically, create it manually:

```bash
mkdir -p ~/.alyncoin
```

The miner will now automatically retry if a block fails to mine during the loop,
so the GUI keeps hashing without manual restarts.

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

Additional details on rolling out the Whisper/TLS update can be found in
[docs/deployment_migration.md](docs/deployment_migration.md).

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
