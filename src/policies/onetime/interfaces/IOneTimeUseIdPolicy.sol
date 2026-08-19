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

    /// @notice Thrown when the witness is zero, which no settlement can present
    error InvalidWitness();

    /// @notice Burns `id` for the caller, nominating the settlement doing it. The caller IS the
    ///         account.
    /// @param id The pinned id
    /// @param witness A value unique to THIS settlement that its ERC-1271 check can also name -
    ///        the Permit2 nonce. Not known at install time; it only has to match within one
    ///        settlement, which is why this design still needs no nonce pinned in advance.
    function consume(uint256 id, uint256 witness) external;

    /// @notice Whether an account's id has been consumed
    function isConsumed(address account, uint256 id) external view returns (bool);
}
