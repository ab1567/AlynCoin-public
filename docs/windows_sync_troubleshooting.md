# Windows Snapshot Sync Troubleshooting

Windows hosts occasionally report repeated `Node far behind` self-healing loops while a full snapshot is streaming from peers. The logs usually show:

```
[SNAPSHOT] ... chunks=NN bytes=...
🚨 Node far behind confirmed. Purging local data and requesting snapshot...
```

The purge resets the partially downloaded snapshot, so the node never catches up.

## Why it Happens

* **Self-heal timing:** the health monitor sees `localHeight == 0` versus a remote tip (>1000) and declares the node "far behind" before the snapshot finishes.
* **Snapshot still active:** on Windows, RocksDB flushes plus antivirus hooks can slow the chunk apply loop. The health check fires before the snapshot completes and triggers another purge.

## Fixes in the Codebase

The `SelfHealingNode` now defers automatic recovery while a snapshot is in progress. Manual (`Run Self-Heal Now`) requests still override the guard if an operator deliberately wants to reset the database.

## Recommended Operator Actions

1. **Keep periodic self-heal enabled** (or set `self_heal_interval` in `config.ini`) – it is now snapshot-aware.
2. **Add antivirus exclusions** for the data directory (default `%USERPROFILE%\.alyncoin\`) to reduce IO pauses.
3. **Avoid storing the data directory inside OneDrive/Dropbox** so file locking does not stall RocksDB writes.
4. **Bootstrap from multiple peers** by populating additional `seed=` entries in `config.ini` to make tip hash probes more reliable.

With these changes, a Windows node should progress through the snapshot once and then transition to normal tail-sync without re-entering the recovery loop.
