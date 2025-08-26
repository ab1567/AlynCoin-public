const { ethers } = require('hardhat');
async function main() {
  const [signer] = await ethers.getSigners();
  const WALYN = await ethers.getContractFactory('WALYN');
  const walyn = await WALYN.deploy();
  await walyn.deployed();
  const Bridge = await ethers.getContractFactory('Bridge');
  const bridge = await Bridge.deploy(walyn.address, [signer.address], 1);
  await bridge.deployed();
  await walyn.transferOwnership(bridge.address);
  console.log('WALYN:', walyn.address);
  console.log('Bridge:', bridge.address);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
