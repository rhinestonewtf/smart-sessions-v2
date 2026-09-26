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

    /// @notice Thrown when `consume`/`consumeFor` executes in a transaction where no `checkAction`
    ///         (of any multiplexer) validated a burn of (caller, id). A diagnostic for a burn op
    ///         that reached execution without validation; the executed op writes nothing either
    /// way.
    error BurnNotValidated(uint256 id);

    /// @notice Thrown when the constructor's intent executor collides with Permit2 or is zero
    error InvalidIntentExecutor();

    /// @notice Emitted when an account's id is burned - at validation, by `checkAction`
    event IdConsumed(address indexed account, uint256 indexed id);

    /// @notice The session's burn op for routes that unlock nothing through Permit2. The burn
    ///         itself happens when `checkAction` validates this op; the execution writes nothing
    ///         and only reverts if no `checkAction` validated a burn of (caller, id) in this
    ///         transaction. The caller IS the account.
    function consume(uint256 id) external;

    /// @notice The session's burn op for a settlement that unlocks through Permit2. Validating it
    ///         burns AND nominates that settlement. The caller IS the account.
    /// @param id The pinned id
    /// @param witness The Permit2 nonce of the settlement this burn nominates; the settling check
    ///        must present the same nonce. Not known at install time; it only has to match within
    ///        one transaction.
    function consumeFor(uint256 id, uint256 witness) external;

    /// @notice Whether an account's id has been burned under `multiplexer` (the SmartSession
    ///         contract that validated the burn)
    function isUsed(address multiplexer, address account, uint256 id) external view returns (bool);

    /// @notice The id pinned for a configuration, whether it has been consumed, and when it expires
    /// @return pinned The pinned id, or zero if the configuration was never initialized
    /// @return consumed Whether that id has been burned under `multiplexer`
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
