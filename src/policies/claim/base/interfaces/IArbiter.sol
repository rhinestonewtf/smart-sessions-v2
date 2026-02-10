// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

/// @title IArbiter
/// @notice Interface for Arbiter contracts used in claim policies.
interface IArbiter {
    /// @notice Calculates the arbiter specific qualification hash from arbitrary bytes data.
    /// @param data Arbitrary bytes data used to compute the qualification hash.
    function qualificationHash(bytes calldata data) external pure returns (bytes32);
}
