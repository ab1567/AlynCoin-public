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
