#!/usr/bin/env node
const { ethers } = require('hardhat');
const fs = require('fs');

async function main() {
  const [,, cmd, ...args] = process.argv;
  if (cmd === 'push-header') {
    const n = parseInt(args[0]);
    const headersAddr = process.env.HEADERS_ADDR;
    if (!headersAddr) throw new Error('HEADERS_ADDR env var required');
    const headers = await ethers.getContractAt('AlynHeaders', headersAddr);
    const data = JSON.parse(fs.readFileSync(__dirname + '/headers.json'));
    for (let i = 0; i < n && i < data.length; i++) {
      const h = data[i];
      const tx = await headers.pushHeader(h.parent, h.txMerkleRoot, h.difficulty, h.nonce);
      await tx.wait();
      console.log('pushed header', i, tx.hash);
    }
  } else if (cmd === 'prove-lock') {
    const lockTx = args[0];
    const headerHash = args[1];
    const bridgeAddr = process.env.BRIDGE_ADDR;
    if (!bridgeAddr) throw new Error('BRIDGE_ADDR env var required');
    const bridge = await ethers.getContractAt('Bridge', bridgeAddr);
    const tx = await bridge.mintWithProof(
      (await ethers.getSigners())[0].address,
      ethers.utils.parseEther('1'),
      headerHash,
      [],
      lockTx
    );
    await tx.wait();
    console.log('mint tx', tx.hash);
  } else {
    console.log('usage: lc push-header <n> | lc prove-lock <lockTxHash> <headerHash>');
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
