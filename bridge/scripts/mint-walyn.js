#!/usr/bin/env node
import 'dotenv/config';
import { JsonRpcProvider, Wallet, Contract, parseUnits } from 'ethers';
import abi from './walyn_abi.json' assert { type: 'json' };

// usage: node mint-walyn.js <recipient> <amount>
const [,, to, amountStr] = process.argv;
if (!to || !amountStr) {
  console.error('usage: node mint-walyn.js <recipient> <amountTokens>');
  process.exit(1);
}

const provider = new JsonRpcProvider(process.env.BSC_RPC);
const wallet = new Wallet(process.env.OWNER_PRIVKEY, provider);
const walyn = new Contract(process.env.WALYN_CONTRACT, abi, wallet);

const amt = parseUnits(amountStr, 18);
const tx = await walyn.mint(to, amt);
console.log('mint tx:', tx.hash);
await tx.wait();
console.log('✅ minted', amountStr, 'wALYN to', to);
