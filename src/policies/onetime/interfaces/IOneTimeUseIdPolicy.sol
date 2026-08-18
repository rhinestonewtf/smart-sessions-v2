// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

/// @title One Time Use Id Policy interface
/// @author Rhinestone
/// @notice Errors, events and views for the settlement-agnostic one-shot marker
interface IOneTimeUseIdPolicy {
    /// @notice Thrown when init data is not exactly one 32-byte id
    error InvalidInitDataLength(uint256 length);

    /// @notice Thrown when a session is pinned to the zero id, which no settlement can present
    error InvalidId();

    /// @notice Emitted when an account's id is consumed, by either burn site
    event IdConsumed(address indexed account, uint256 indexed id);

    /// @notice Burns `id` for the caller. The caller IS the account.
    function consume(uint256 id) external;

    /// @notice Whether an account's id has been consumed
    function isConsumed(address account, uint256 id) external view returns (bool);
}
