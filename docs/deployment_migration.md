# Deployment & Migration

This document describes how to safely roll out the Whisper and TLS features
without breaking compatibility with existing AlynCoin nodes.

## Version bump

The network frame revision is bumped to `3`. All nodes advertise the
capabilities `whisper_v1` and `tls_v1` in their handshakes. The
`enable_whisper` and `enable_tls` flags control whether those features are
actively used.

## Compatibility fallback

When a peer does not advertise `whisper_v1` the node falls back to the classic
`broadcastTransaction()` path instead of using onion routing.

## Database upgrade

`peers.txt` lines now optionally include a base64 encoded shared key:

```
<ip>:<port> <base64 shared key>
```

Loading peers will parse the key if present and populate the peer's `linkKey`.
Saving peers writes the key back to disk so connections survive restarts.

## Testing pipeline

1. **Unit test** – verify `sphinx::createPacket` and `peelPacket` round trip.
2. **Integration** – run two local nodes with three dummy relays and confirm
   transactions arrive while relays only see onion blobs.
3. **Load test** – send 1000 transactions per minute and ensure the rate limit
   triggers above the threshold.

## Gradual enable

Both `enable_tls` and `enable_whisper` default to `false`. Once 40% of known
peers advertise the new capabilities the defaults can be flipped to `true`.

## Public reachability

Recent releases align the peer-to-peer handshake with the behaviour used by
Bitcoin and Ethereum:

- Every node now advertises a stable handshake nonce so self-connections can be
  detected reliably even when NAT hairpinning is enabled.
- Peers echo the IP address they observe during the handshake; nodes learn the
  first routable public address and include it in subsequent outbound
  handshakes.
- Duplicate connections are de-duplicated deterministically by comparing the
  remote handshake nonce rather than using lexical IP ordering. This allows
  both sides to dial simultaneously without forming connection storms.
- Peer list gossip now skips private, loopback, link-local, and carrier-grade
  NAT ranges so the network no longer circulates unroutable endpoints.

To make a node reachable by the wider network you still need to forward TCP
port `15671` (or enable UPnP/NAT-PMP). Without an open inbound port a node will
be limited to outbound connections only, just like standard Bitcoin/Ethereum
deployments.
