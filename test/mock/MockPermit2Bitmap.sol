// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

/// @title Mock Permit2 Bitmap
/// @notice Minimal stand-in exposing Permit2's public nonce bitmap
contract MockPermit2Bitmap {
    mapping(address => mapping(uint256 => uint256)) public nonceBitmap;

    /// @notice Marks a nonce consumed using Permit2's own word/bit split
    function burn(address owner, uint256 nonce) external {
        nonceBitmap[owner][nonce >> 8] |= uint256(1) << (nonce & 0xff);
    }
}
