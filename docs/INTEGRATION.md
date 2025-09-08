# Exchange Integration Guide

This document outlines the minimal information required to integrate AlynCoin
(ALYN) with exchanges or explorers.

## Network
- **P2P Port:** 15671
- **RPC Port:** 1567 (`http://<host>:1567`)
- **Block Time:** 30 seconds
- **Consensus:** BLAKE3/Keccak proof-of-work

## RPC Endpoints
- `chain.getInfo`
- `chain.getSupply`
- `address.getBalance`
- `bridge.getPoR`

See `docs/RPC.md` for request and response examples.

## Deposit / Confirmation Rules
- Transactions should be considered final after **20 confirmations**.
- Use `address.getBalance` to verify credits.

## Node Build
- Static binaries available for Linux, Windows and macOS. See `packaging/`.
- Docker image provided under `docker/`.
