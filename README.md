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

These allocations are minted to dedicated addresses at genesis and count toward the 100 million coin cap.

### Premine addresses

| Allocation        | Wallet Address                             |
|-------------------|--------------------------------------------|
| Airdrops          | `9a3d60db8c4aa4e56d4af1e2ca08add8613ad10f` |
| Liquidity         | `48cb2ae09f550de06f0caff91fb9690e95c9bbc3` |
| Investors         | `806cc16a6f7235f09bc753923c2c15b721c8f442` |
| Development       | `406317234be65bf7cc6e8e117b3404a4260f657d` |
| Exchange Listings | `0267d5c4d63c4223a9ae9ac8ada00dd75357be31` |
| Team/Founder      | `d823146d399e22d35739c78cef0ad8ff664311f5` |

These canonical addresses are the long-term source of truth on-chain. The
client still exposes `resolveWalletKeyIdentifier`, but it now resolves a wallet
by matching the address to locally stored public keys or an operator-defined key
prefix. Keeping the premine keyed solely by address avoids shipping extra alias
material in the binary and ensures the canonical hash remains the stable,
tamper-evident reference going forward.

Block rewards decline as circulating supply approaches the cap. A portion of
transaction fees is burned while another portion funds ongoing development via
the DAO treasury. The team allocation is locked for one year and vests
linearly over the following three years.

### Wrapped WALYN

To support cross-chain liquidity and exchange listings, a wrapped ERC-20
version of AlynCoin called **WALYN** will be issued. Each WALYN token is backed
1:1 by ALYN held in reserve addresses. An initial allocation of **300,000
WALYN** is reserved for the Tokpie exchange to seed liquidity for wrapped
trading pairs.

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
  libspdlog-dev libnatpmp-dev \
  zip unzip git curl python3 python3-pip

# UPnP NAT traversal library
sudo apt install -y libminiupnpc-dev

> **Note:** NAT-PMP port mapping is optional. If you do not need it, you can
> remove `libnatpmp-dev` from the package list above and the build will disable
> NAT-PMP automatically.
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

On Windows builds that use vcpkg, install the NAT-PMP package alongside the
other dependencies before generating build files:

```powershell
vcpkg install libnatpmp:x64-windows-static
```

Run the basic unit tests to verify the build:

```bash
make blacklist_test
./blacklist_test
```

### RocksDB storage footprint

All RocksDB consumers (the core chain, explorers, identity, swaps, etc.) call
`ApplyDatabaseDefaults` before opening the database.  The helper enables
Zstandard compression and tuned compaction targets so new SST files are 3–5×
smaller than the uncompressed baseline.  See [`docs/storage_tuning.md`](docs/storage_tuning.md)
for a breakdown of the settings and how to override them if you need to run
benchmarks without compression.

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

Peers can be listed in `peers.txt` under your configured data directory (default
`data/peers.txt`) or specified on the command line. To join the public test
network, run:

```bash
./build/alyncoin --connect <peer_ip>
```

The default RPC port is `1567` and the peer port is `15671`.

> **Peer count tip:** the number displayed in the GUI banner represents only the
> **remote** peers your node is connected to. When you run exactly two nodes,
> each one will report a single peer because it only counts the other node, not
> itself. The node now persists any peers it contacts (including via
> `--connect`) into `peers.txt` (stored under `data_dir`) and falls back to the
> built-in bootstrap list if
> the file is empty, so you rarely need to edit it manually. Opening TCP `15671`
> for inbound connections still helps other nodes reach you and increases the
> banner count more quickly.

Nodes now relay any peers discovered via DNS to all connected nodes shortly
after startup. This helps the mesh stay connected even if the DNS seed becomes
unreachable.

Recent hardening focuses on keeping the node synchronized without operator
intervention:

- **Self-endpoint detection** filters outbound dials that target the node's own
  public interfaces or cached self-learned endpoints, preventing the
  self-connection loop that previously left freshly restarted nodes isolated.
- **Fork recovery improvements** escalate header-bridge requests until a last
  common ancestor is found. Once identified, the node replays the heavier branch
  automatically so medium-depth forks heal without manual restarts.

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
interactive node. Run `./alyncoin-cli --help` to see available commands and
usage examples. When creating a wallet, the CLI now prompts for a passphrase
(minimum 8 characters) to encrypt your keys.

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

The wallet stores keys in `~/.alyncoin/keys`. Ensure this directory is writable
by your user. If the GUI fails to create it automatically, create it manually:

```bash
mkdir -p ~/.alyncoin/keys
```

Each wallet consists of three key files suffixed with `_private.pem`,
`_dilithium.key`, and `_falcon.key`. If a passphrase is used, a hashed
passphrase is stored alongside them as `<name>_pass.txt` in the same
directory.

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
