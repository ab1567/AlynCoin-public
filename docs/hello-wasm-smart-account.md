# Hello Wasm Smart Account

This tutorial walks through building and interacting with the example contracts using the `alyn-sdk`.

## Build

```bash
# smart wallet
cd contracts/smart_wallet
cargo build --target wasm32-unknown-unknown --release
# multisig wallet
cd ../multisig_wallet
cargo build --target wasm32-unknown-unknown --release
```

Both commands produce `.wasm` artifacts under `target/wasm32-unknown-unknown/release/`.

## Deploy

```ts
import { deploy, encodeL2Tx } from '../alyn-sdk';
import { readFileSync } from 'fs';

const wasm = readFileSync('contracts/smart_wallet/target/wasm32-unknown-unknown/release/smart_wallet.wasm');
const tx = { to: '0x00', data: new Uint8Array(wasm) };
await deploy('http://localhost:8545', tx);
```

## Call

```ts
import { call, encodeCalldata } from '../alyn-sdk';

const calldata = encodeCalldata('entry', Uint8Array.from([1,2,3]));
await call('http://localhost:8545', { to: '0xdead', data: calldata });
```

## Query Storage

```ts
import { query } from '../alyn-sdk';
const res = await query('http://localhost:8545', { to: '0xdead', data: new Uint8Array() });
console.log(res); // returns storage and emitted events
```
