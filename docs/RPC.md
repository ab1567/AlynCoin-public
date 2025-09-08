# JSON-RPC API

The AlynCoin daemon exposes a JSON-RPC interface on the HTTP `/rpc` endpoint.
All calls use standard JSON-RPC 2.0 messages.

## chain.getInfo
Returns general node information.

```
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "chain.getInfo",
  "params": {}
}
```

## chain.getSupply
Returns total, burned, locked and circulating supply.

## address.getBalance
Parameters: `{ "address": "<ALYN_ADDR>" }`

Returns the balance for the given address or an error for invalid input.

## system.selfHealNow
Triggers a health check and returns `{ "ok": true }` when scheduled.

## bridge.getPoR
Provides Proof-of-Reserves data when the bridge reserve address and expected
wrapped supply are configured.
