// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

/// @title IIntentExecutorNonces
/// @author Rhinestone
/// @notice The intent executor's consumed-nonce views, across all three of its namespaces
/// @dev `IntentExecutor` is one contract inheriting the compact, Permit2-stub and standalone
/// executors, each of which burns the same nonce value into a namespace of its own. Reading one
/// namespace answers "not settled" for a settlement that went through either of the others, so a
/// caller asking whether the executor has spent a nonce must ask about all three
interface IIntentExecutorNonces {
    /// @notice Whether a standalone-intent settlement consumed this nonce
    /// @param nonce The nonce to check
    /// @param account The account the nonce belongs to
    /// @return used True if the nonce is consumed
    function isStandaloneIntentNonceConsumed(
        uint256 nonce,
        address account
    )
        external
        view
        returns (bool used);

    /// @notice Whether a Permit2-stub settlement consumed this nonce
    /// @dev Despite the name this is the executor's OWN namespace; it never touches Permit2
    /// @param nonce The nonce to check
    /// @param account The account the nonce belongs to
    /// @return used True if the nonce is consumed
    function isPermit2IntentNonceConsumed(
        uint256 nonce,
        address account
    )
        external
        view
        returns (bool used);

    /// @notice Whether a compact-stub settlement consumed this nonce
    /// @param nonce The nonce to check
    /// @param account The account the nonce belongs to
    /// @return used True if the nonce is consumed
    function isCompactIntentNonceConsumed(
        uint256 nonce,
        address account
    )
        external
        view
        returns (bool used);
}
