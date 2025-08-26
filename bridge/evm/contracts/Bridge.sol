// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import './WALYN.sol';
import '@openzeppelin/contracts/utils/cryptography/ECDSA.sol';

contract Bridge {
    using ECDSA for bytes32;

    WALYN public token;
    mapping(address => bool) public signers;
    uint256 public threshold;
    mapping(bytes32 => bool) public processed;

    event Mint(address indexed to, uint256 amount, bytes32 indexed lockTx);
    event Burn(address indexed from, uint256 amount, bytes32 indexed burnId);

    constructor(address tokenAddr, address[] memory _signers, uint256 _threshold) {
        token = WALYN(tokenAddr);
        for (uint256 i = 0; i < _signers.length; i++) {
            signers[_signers[i]] = true;
        }
        threshold = _threshold;
    }

    function mint(address to, uint256 amount, bytes32 lockTx, bytes[] calldata sigs) external {
        bytes32 msgHash = keccak256(abi.encodePacked(to, amount, lockTx, address(this))).toEthSignedMessageHash();
        require(!processed[msgHash], 'processed');
        uint256 valid;
        address[] memory seen = new address[](sigs.length);
        for (uint256 i = 0; i < sigs.length; i++) {
            address signer = msgHash.recover(sigs[i]);
            require(signers[signer], 'bad signer');
            for (uint256 j = 0; j < i; j++) {
                require(signer != seen[j], 'duplicate');
            }
            seen[i] = signer;
            valid++;
        }
        require(valid >= threshold, 'not enough sigs');
        processed[msgHash] = true;
        token.mint(to, amount);
        emit Mint(to, amount, lockTx);
    }

    function burn(uint256 amount, bytes32 burnId) external {
        token.burn(msg.sender, amount);
        emit Burn(msg.sender, amount, burnId);
    }
}
