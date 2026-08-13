// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

/// @title Permit2 Header Library
/// @author Rhinestone
/// @notice Byte offsets of the Permit2 claim payload header, shared by everything that reads it
/// @dev One source of truth. A second copy of these offsets drifts silently: a policy reading a
///      stale window returns a wrong boolean rather than reverting.
library Permit2HeaderLib {
    /// @dev arbiter (Permit2 spender) occupies [0:20]
    uint256 internal constant ARBITER_START = 0;
    uint256 internal constant ARBITER_END = 20;

    /// @dev nonce occupies [20:52]
    uint256 internal constant NONCE_START = 20;
    uint256 internal constant NONCE_END = 52;

    /// @dev deadline occupies [52:84]
    uint256 internal constant DEADLINE_START = 52;
    uint256 internal constant DEADLINE_END = 84;

    /// @dev Total header size; the mandate follows
    uint256 internal constant HEADER_END = 84;

    /// @notice Reads the nonce out of a Permit2 claim payload
    /// @dev Caller must ensure `data` is at least `NONCE_END` bytes
    function nonce(bytes calldata data) internal pure returns (uint256) {
        return uint256(bytes32(data[NONCE_START:NONCE_END]));
    }
}
