// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/contracts/access/Ownable2Step.sol";

/// @title Wrapped AlynCoin (wALYN)
/// @notice 1:1 representation of native AlynCoin on BNB Smart Chain.
contract WrappedAlynCoin is ERC20, ERC20Burnable, Ownable2Step {
    constructor() ERC20("Wrapped AlynCoin", "wALYN") {}

    /// @notice Mint tokens to an address. Restricted to bridge custodian.
    function mint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
    }
}

