// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

/// @title Permit2 Sender Policy interface
/// @author Rhinestone
/// @notice Errors for the Permit2 sender policy
interface IPermit2SenderPolicy {
    /// @notice Thrown when the constructor's Permit2 is the zero address
    error InvalidPermit2();

    /// @notice Thrown when init data is not empty: the policy takes no configuration
    error InvalidInitDataLength(uint256 length);
}
