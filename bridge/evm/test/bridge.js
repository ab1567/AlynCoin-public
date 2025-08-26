const { expect } = require('chai');
const { ethers } = require('hardhat');

describe('WALYN Bridge', function () {
  let walyn, bridge, signer1, signer2, user;
  beforeEach(async function () {
    [owner, signer1, signer2, user] = await ethers.getSigners();
    const WALYN = await ethers.getContractFactory('WALYN');
    walyn = await WALYN.deploy();
    await walyn.deployed();
    const Bridge = await ethers.getContractFactory('Bridge');
    bridge = await Bridge.deploy(walyn.address, [signer1.address, signer2.address], 2);
    await bridge.deployed();
    await walyn.transferOwnership(bridge.address);
  });

  it('mints after lock event', async function () {
    const to = user.address;
    const amount = ethers.utils.parseEther('10');
    const lockTx = ethers.utils.hexlify(ethers.utils.randomBytes(32));
    const msgHash = ethers.utils.solidityKeccak256(['address','uint256','bytes32','address'], [to, amount, lockTx, bridge.address]);
    const sig1 = await signer1.signMessage(ethers.utils.arrayify(msgHash));
    const sig2 = await signer2.signMessage(ethers.utils.arrayify(msgHash));
    await bridge.mint(to, amount, lockTx, [sig1, sig2]);
    expect(await walyn.balanceOf(to)).to.equal(amount);
  });

  it('burns and emits release event', async function () {
    const to = user.address;
    const amount = ethers.utils.parseEther('5');
    const lockTx = ethers.utils.hexlify(ethers.utils.randomBytes(32));
    const msgHash = ethers.utils.solidityKeccak256(['address','uint256','bytes32','address'], [to, amount, lockTx, bridge.address]);
    const sig1 = await signer1.signMessage(ethers.utils.arrayify(msgHash));
    const sig2 = await signer2.signMessage(ethers.utils.arrayify(msgHash));
    await bridge.mint(to, amount, lockTx, [sig1, sig2]);
    await walyn.connect(user).approve(bridge.address, amount);
    const burnId = ethers.utils.hexlify(ethers.utils.randomBytes(32));
    await expect(bridge.connect(user).burn(amount, burnId)).to.emit(bridge, 'Burn').withArgs(user.address, amount, burnId);
    expect(await walyn.balanceOf(user.address)).to.equal(0);
  });
});
