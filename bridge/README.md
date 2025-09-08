# wALYN Bridge

Wrapped AlynCoin (wALYN) is a BEP-20 token on BNB Smart Chain representing native
AlynCoin (ALYN) at a 1:1 ratio. A multisig custodian holds the ALYN reserves and
controls minting and burning of wALYN. The Solidity contract uses OpenZeppelin
Contracts v4.9.

## Addresses
- **wALYN contract:** `0x...` (BscScan link)
- **Custodian multisig:** `0x...`
- **ALYN reserve address:** `ALYN1...` (AlynCoin explorer link)

## Minting / Burning
1. User sends native ALYN to the reserve address and requests wrapping.
2. Custodian runs `node bridge/scripts/mint-walyn.js <recipient> <amount>`.
3. To unwrap, user approves tokens and custodian runs
   `node bridge/scripts/burn-walyn.js <from> <amount>` then transfers
   native ALYN back to the user.

## Proof-of-Reserves
Run `node bridge/scripts/por-check.js` to compare total wALYN supply against the
reported native ALYN reserves. A status of `MATCH` indicates a 1:1 peg.
