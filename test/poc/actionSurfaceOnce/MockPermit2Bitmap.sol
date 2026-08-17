// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

/// @title MockPermit2Bitmap
/// @notice Stands in for Permit2's unordered-nonce bitmap, which is the consumable Across and Eco
///         share. Only `nonceBitmap` is reachable from the policy under test; `burn` exists so a
///         test can place the bitmap in the state a real settlement would have left it in.
contract MockPermit2Bitmap {
    mapping(address owner => mapping(uint256 wordPos => uint256 bits)) internal $bitmap;

    function nonceBitmap(address owner, uint256 wordPos) external view returns (uint256) {
        return $bitmap[owner][wordPos];
    }

    /// @notice Marks `nonce` spent for `owner`, the way `permitWitnessTransferFrom` would
    function burn(address owner, uint256 nonce) external {
        $bitmap[owner][nonce >> 8] |= 1 << (nonce & 0xff);
    }
}
