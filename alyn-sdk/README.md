# Alyn SDK

Minimal helpers for interacting with the AlynCoin Layer-2 interface.

## Usage

```ts
import { encodeL2Tx, deploy, call, query, encodeCalldata } from 'alyn-sdk';

const tx = { to: '0x00', data: new Uint8Array([1,2,3]) };
await deploy('http://localhost:8545', tx);
```

See `docs/hello-wasm-smart-account.md` for a full tutorial.
