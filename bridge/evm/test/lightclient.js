const { expect } = require('chai');
const { ethers } = require('hardhat');

describe('Alyn light client bridge', function () {
  let walyn, headers, bridge, owner, signer1, signer2, user;

  beforeEach(async function () {
    [owner, signer1, signer2, user] = await ethers.getSigners();

    const WALYN = await ethers.getContractFactory('WALYN');
    walyn = await WALYN.deploy();
    await walyn.deployed();

    // prepare genesis header
    const parent = ethers.constants.HashZero;
    const txRoot = ethers.utils.keccak256(ethers.utils.toUtf8Bytes('genesis'));
    const difficulty = 1;
    const nonce = 0;
    const genesisHash = ethers.utils.keccak256(
      ethers.utils.defaultAbiCoder.encode(
        ['bytes32', 'bytes32', 'uint256', 'uint256'],
        [parent, txRoot, difficulty, nonce]
      )
    );
    const AlynHeaders = await ethers.getContractFactory('AlynHeaders');
    headers = await AlynHeaders.deploy(genesisHash, txRoot, difficulty);
    await headers.deployed();

    const Bridge = await ethers.getContractFactory('Bridge');
    bridge = await Bridge.deploy(walyn.address, [signer1.address, signer2.address], 2, headers.address);
    await bridge.deployed();
    await walyn.transferOwnership(bridge.address);
    await bridge.enableTrustless(true);
  });

  it('mints with valid header and proof', async function () {
    const lockTx = ethers.utils.keccak256(ethers.utils.toUtf8Bytes('lockTx'));
    const parent = await headers.tip();
    const txRoot = lockTx; // simple merkle tree with single tx
    const difficulty = 1;
    const nonce = 1;
    await headers.pushHeader(parent, txRoot, difficulty, nonce);
    const headerHash = await headers.tip();
    await bridge.mintWithProof(user.address, ethers.utils.parseEther('1'), headerHash, [], lockTx);
    expect(await walyn.balanceOf(user.address)).to.equal(ethers.utils.parseEther('1'));
  });

  it('rejects invalid proof', async function () {
    const lockTx = ethers.utils.keccak256(ethers.utils.toUtf8Bytes('lockTx'));
    const wrongTx = ethers.utils.keccak256(ethers.utils.toUtf8Bytes('other'));
    const parent = await headers.tip();
    const txRoot = lockTx;
    const difficulty = 1;
    const nonce = 1;
    await headers.pushHeader(parent, txRoot, difficulty, nonce);
    const headerHash = await headers.tip();
    await expect(
      bridge.mintWithProof(user.address, ethers.utils.parseEther('1'), headerHash, [], wrongTx)
    ).to.be.revertedWith('invalid proof');
  });
});
