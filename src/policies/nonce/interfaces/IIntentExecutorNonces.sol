// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

/// @title IIntentExecutorNonces
/// @author Rhinestone
/// @notice The intent executor's consumed-nonce views, across all three of its nonce namespaces
/// @dev `IntentExecutor` is one contract inheriting the compact, Permit2 and standalone executors,
/// each of which burns the same nonce value into a namespace of its own. Reading a single
/// namespace answers "not settled" for a settlement that went through either of the other two, so
/// this policy takes one handle covering all three rather than the per-family interfaces
interface IIntentExecutorNonces {
    /// @notice The settlement whose signature the executor is validating right now
    /// @dev Transient, live only for the duration of one signature check. This is what binds a
    /// policy to the settlement in front of it; the consumed views below cannot, being permanent
    /// @return active Whether a settlement signature is being validated right now
    /// @return account The account that settlement settles for, meaningless when active is false
    /// @return nonce The nonce of that settlement, meaningless when active is false
    function currentIntentNonce()
        external
        view
        returns (bool active, address account, uint256 nonce);

    /// @notice Whether a family other than the one settling right now already settled this nonce
    /// @dev Only the executor can answer this, since only it knows which of its three consumables
    /// the settlement in flight burns; the families also differ on whether they burn before or
    /// after validating, so counting consumed slots from outside cannot substitute
    /// @param nonce The nonce to check
    /// @param account The account the nonce belongs to
    /// @return settled True if another family has already consumed this nonce for this account
    function isIntentNonceSettledElsewhere(
        uint256 nonce,
        address account
    )
        external
        view
        returns (bool settled);

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
