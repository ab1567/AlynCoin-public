# AlynCoin Architecture

## Async Verifier Flow
```mermaid
flowchart TD
    A[Receive Block] --> B{Async verify enabled?}
    B -- yes --> C[verifyQueue]
    C --> D[Verifier Threads]
    D --> E[handleNewBlock]
    B -- no --> E
```

## INV/GETDATA Handshake
```mermaid
sequenceDiagram
    participant A as Node A
    participant B as Node B
    A->>B: INV(block hash)
    B-->>A: GETDATA(block hash)
    A->>B: BLOCK
```

## Per-Peer Writer Threads
```mermaid
flowchart LR
    subgraph Peer
        TxQueue --> WriterThread
        WriterThread --> Socket
    end
```

### Network Scaling Features
- **Async verification threads** scale with `verify_threads` (default: twice CPU cores).
- **Orphan pool** holds up to 5000 blocks and retries them when parents arrive.
- **Rate limiter** drops messages from noisy peers using a token bucket.
