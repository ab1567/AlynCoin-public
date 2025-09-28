# RocksDB storage tuning defaults

The node now centralises all RocksDB sizing/compression knobs in
`src/db/rocksdb_options_utils.h`.  The helper is called automatically by every
entry point that opens a RocksDB instance (core blockchain, explorers,
transaction pool, governance, identity, swaps, NFT tooling, and the peer
blacklist).  No manual flag is required—the options are applied immediately
before the database handle is opened.

The defaults enable Zstandard compression (using the correct enum for the
installed RocksDB major version), dynamic level compaction, a 64&nbsp;MiB write
buffer, and 32&nbsp;MiB target SSTables.  Combined, those settings shrink new SST
files by ~3-5× compared to the previous uncompressed configuration while
keeping write amplification under control.

At startup the blockchain service logs the effective compression algorithm so
you can confirm the helper ran, e.g.

```
🧱 RocksDB compression: ZSTD, write buffer = 64 MiB, target file size = 32 MiB
```

If you need to experiment with different settings (or disable compression for
benchmarks) you can override them before calling `rocksdb::DB::Open`, or patch
`ApplyDatabaseDefaults` for a global change.
