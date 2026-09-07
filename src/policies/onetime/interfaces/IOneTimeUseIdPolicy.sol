// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

import { ConfigId } from "@smartsessions/DataTypes.sol";

/// @title One Time Use Id Policy interface
/// @author Rhinestone
/// @notice Errors, events and views for the settlement-agnostic one-shot marker
interface IOneTimeUseIdPolicy {
    /// @notice Thrown when init data is not exactly a 32-byte id followed by a 32-byte deadline
    error InvalidInitDataLength(uint256 length);

    /// @notice Thrown when initializing a session with the zero id, which marks "not configured"
    error InvalidId();

    /// @notice Thrown when initializing with a deadline that has already passed, which would pin a
    ///         session no settlement could ever use
    error DeadlineInPast(uint256 deadline, uint256 timestamp);

    /// @notice Thrown when `consume` is called for an id already burned for the caller
    error AlreadyConsumed(uint256 id);

    /// @notice Thrown when the constructor's intent executor collides with Permit2 or is zero
    error InvalidIntentExecutor();

    /// @notice Emitted when an account's id is consumed, by either burn site
    event IdConsumed(address indexed account, uint256 indexed id);

    /// @notice Burns `id` for the caller WITHOUT nominating any settlement. The caller IS the
    ///         account. This is the burn for routes gated by `checkAction`, which is strict and
    ///         reads the durable record directly, so it needs no nomination.
    function consume(uint256 id) external;

    /// @notice Burns `id` AND nominates the settlement doing it. The caller IS the account.
    /// @dev Only the ERC-1271 route needs this: it validates twice with the burn in between, so
    ///      its settling check must be able to tell its own burn from someone else's.
    /// @param id The pinned id
    /// @param witness A value unique to THIS settlement that its settling check can also name -
    ///        the Permit2 nonce. Not known at install time; it only has to match within one
    ///        settlement, which is why this design still needs no nonce pinned in advance.
    function consumeFor(uint256 id, uint256 witness) external;

    /// @notice Whether an account's id has been consumed
    function isUsed(address account, uint256 id) external view returns (bool);

    /// @notice The id pinned for a configuration, whether it has been consumed, and when it expires
    /// @return pinned The pinned id, or zero if the configuration was never initialized
    /// @return consumed Whether that id has been burned
    /// @return deadline The last timestamp a settlement may use it, or zero if it never expires
    function usage(
        ConfigId configId,
        address multiplexer,
        address account
    )
        external
        view
        returns (uint256 pinned, bool consumed, uint256 deadline);
}
