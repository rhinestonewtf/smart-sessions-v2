// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

/// @title Mock Standalone Intent
/// @notice Minimal stand-in exposing the executor's consumed-nonce view
contract MockStandaloneIntent {
    mapping(uint256 nonce => mapping(address account => bool)) internal $consumed;

    function setConsumed(uint256 nonce, address account, bool consumed) external {
        $consumed[nonce][account] = consumed;
    }

    function isStandaloneIntentNonceConsumed(
        uint256 nonce,
        address account
    )
        external
        view
        returns (bool)
    {
        return $consumed[nonce][account];
    }
}
