// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/// @title Wrapped AlynCoin (wALYN)
/// @notice 1:1 representation of native AlynCoin on BNB Smart Chain.
contract WrappedAlynCoin is ERC20, Ownable {
    /// @param initialSupply Amount of tokens to mint on deployment (18 decimals).
    constructor(uint256 initialSupply) ERC20("Wrapped AlynCoin", "wALYN") {
        _mint(msg.sender, initialSupply);
    }

    /// @notice Mint tokens to an address. Restricted to bridge custodian.
    function mint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
    }

    /// @notice Burn tokens from an address. Restricted to bridge custodian.
    function burn(address from, uint256 amount) external onlyOwner {
        _burn(from, amount);
    }
}

