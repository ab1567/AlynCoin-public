#!/usr/bin/env node
import 'dotenv/config';
import { JsonRpcProvider, Contract, formatUnits } from 'ethers';
import abi from './walyn_abi.json' assert { type: 'json' };

const provider = new JsonRpcProvider(process.env.BSC_RPC);
const walyn = new Contract(process.env.WALYN_CONTRACT, abi, provider);

// In absence of native chain API, expected reserve is supplied via env
const supply = await walyn.totalSupply();
const total = parseFloat(formatUnits(supply, 18));
const reserve = parseFloat(process.env.ALYN_RESERVE_EXPECTED || '0');
const delta = reserve - total;
const ok = Math.abs(delta) < 1e-9;

console.log(JSON.stringify({
  timestamp: new Date().toISOString(),
  walyn_supply: total,
  alyn_reserve: reserve,
  delta,
  status: ok ? 'MATCH' : 'MISMATCH'
}, null, 2));

process.exit(ok ? 0 : 1);
