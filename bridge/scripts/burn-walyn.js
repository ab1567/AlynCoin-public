#!/usr/bin/env node
import 'dotenv/config';
import { JsonRpcProvider, Wallet, Contract, parseUnits } from 'ethers';
import abi from './walyn_abi.json' assert { type: 'json' };

// usage: node burn-walyn.js <from> <amount>
const [,, from, amountStr] = process.argv;
if (!from || !amountStr) {
  console.error('usage: node burn-walyn.js <from> <amountTokens>');
  process.exit(1);
}

const provider = new JsonRpcProvider(process.env.BSC_RPC);
const wallet = new Wallet(process.env.OWNER_PRIVKEY, provider);
const walyn = new Contract(process.env.WALYN_CONTRACT, abi, wallet);

const amt = parseUnits(amountStr, 18);
const tx = await walyn.burnFrom(from, amt);
console.log('burn tx:', tx.hash);
await tx.wait();
console.log('✅ burned', amountStr, 'wALYN from', from);
