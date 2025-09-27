# Sync Strategy Options

## Current Snapshot Flow
- `Network::sendSnapshot` enforces a per-peer cooldown, validates preferred chunk sizes, streams snapshot metadata, and chunks data according to the negotiated limit before marking completion. This guards against duplicate transfers and network congestion.
- Each `PeerState` caches handshake-derived capability flags, snapshot preferences, and the last time a snapshot was served so we can respect peer limits and throttle resend attempts.
- During the handshake we record the remote node's snapshot chunk preference and fall back to tail-sync when the peer is already near our height.

## Complementary Mechanisms Already Present
- Tail-sync requests allow peers that are only a few blocks behind to stream recent history without replaying the full snapshot.
- Epoch and aggregate proof responses support lighter-weight validation without resending full chain data when a peer only needs checkpoints.

## Options Observed in Other Networks
- **Ethereum Snap Sync / Beam Sync**: peers exchange recent headers then reconstruct state trie data on-demand, reducing upfront snapshot cost at the expense of more complex state proof handling.
- **Bitcoin Compact Block Relay (BIP 152)**: synchronizes by fetching block headers and thin block bodies leveraging inventory announcements; requires accurate mempool / block templates but eliminates explicit snapshots.
- **Zcash Flyclient-style proofs**: rely on succinct proofs-of-proof-of-work to skip directly to a recent tip, requiring Merkle Mountain Range commitments baked into consensus.

## Potential Enhancements for AlynCoin
- Add a "header-first" fast sync path that primes the chain via header download before requesting full blocks, similar to Bitcoin Core's headers-first mode, using the existing `requestBlockByHash` primitive.
- Implement partial state proofs (e.g., account trie chunks or balance checkpoints) so that tail-sync nodes can validate without the full snapshot volume, at the cost of maintaining additional commitment structures.
- Integrate a beam-sync style mechanism where peers stream execution traces or state diffs as blocks arrive, reducing the need for full snapshots except on cold start.

These approaches generally trade implementation complexity for reduced bandwidth / startup time. For short-term reliability, the current snapshot + tail-sync combination remains the lowest-risk baseline. Longer term, combining tail-sync with lighter-weight state proofs would move the protocol closer to market standards without abandoning the existing snapshot safety net.
