#!/usr/bin/env node
import 'dotenv/config';
import { JsonRpcProvider, Contract, formatUnits, parseUnits } from 'ethers';
import abi from './walyn_abi.json' assert { type: 'json' };

// Provider + contract
const provider = new JsonRpcProvider(process.env.BSC_RPC);
const walyn = new Contract(process.env.WALYN_CONTRACT, abi, provider);

// On-chain supply (BigInt) and expected reserve (BigInt)
const supply = await walyn.totalSupply();
const expected = parseUnits(process.env.ALYN_RESERVE_EXPECTED || '0', 18);

const delta = expected - supply;
const ok = delta === 0n;

const out = {
  timestamp: new Date().toISOString(),
  walyn_supply: formatUnits(supply, 18),
  alyn_reserve: formatUnits(expected, 18),
  delta: formatUnits(delta, 18),
  status: ok ? 'MATCH' : 'MISMATCH'
};

console.log(JSON.stringify(out, null, 2));
process.exit(ok ? 0 : 1);
