// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

import { ConfigId } from "@smartsessions/DataTypes.sol";
import { EfficientHashLib } from "@solady/utils/EfficientHashLib.sol";

/// @title One Time Use Id Storage Library
/// @author Rhinestone
/// @notice Namespaced storage for OneTimeUseIdPolicy: the pinned id per configuration, the spend
/// per (id, account), and the transient per-settlement nomination.
library OneTimeUseIdStorageLib {
    /// @dev keccak256("rhinestone.storage.OneTimeUseIdPolicy.pin") - 1
    bytes32 internal constant PIN_POSITION =
        bytes32(uint256(keccak256("rhinestone.storage.OneTimeUseIdPolicy.pin")) - 1);

    /// @dev keccak256("rhinestone.storage.OneTimeUseIdPolicy.spend") - 1
    bytes32 internal constant SPEND_POSITION =
        bytes32(uint256(keccak256("rhinestone.storage.OneTimeUseIdPolicy.spend")) - 1);

    /// @dev keccak256("rhinestone.storage.OneTimeUseIdPolicy.nomination") - 1
    bytes32 internal constant NOMINATION_POSITION =
        bytes32(uint256(keccak256("rhinestone.storage.OneTimeUseIdPolicy.nomination")) - 1);

    /// @dev Nomination value meaning no settlement was nominated in this transaction
    uint256 internal constant NOT_NOMINATED = 0;

    /// @dev Deadline value meaning the pinned id never expires
    uint256 internal constant NO_DEADLINE = 0;

    /// @dev Zero id means "not configured"; zero deadline means "never expires"
    struct PinStorage {
        uint256 id;
        uint256 deadline;
    }

    struct SpendStorage {
        bool burned;
    }

    /// @notice The pinned id for a (configId, multiplexer, account)
    function pin(
        ConfigId configId,
        address multiplexer,
        address account
    )
        internal
        pure
        returns (PinStorage storage $)
    {
        bytes32 slot = EfficientHashLib.hash(
            PIN_POSITION,
            ConfigId.unwrap(configId),
            bytes32(uint256(uint160(multiplexer))),
            bytes32(uint256(uint160(account)))
        );
        assembly {
            $.slot := slot
        }
    }

    /// @notice The spend record for an (id, account). Not keyed by configId so it is reachable from
    ///         `consume` (called by the account, which knows no configId) and shared across a
    ///         session's policy surfaces, which SmartSessions gives distinct configIds.
    function spendRecord(
        uint256 id,
        address account
    )
        internal
        pure
        returns (SpendStorage storage $)
    {
        bytes32 slot =
            EfficientHashLib.hash(SPEND_POSITION, bytes32(id), bytes32(uint256(uint160(account))));
        assembly {
            $.slot := slot
        }
    }

    /// @notice Whether `deadline` has passed. Inclusive, matching Permit2's own
    ///         `block.timestamp > deadline` rule, so a settlement is still valid in the block the
    ///         deadline names. One predicate for both the install-time rejection and the two read
    ///         surfaces, so install refuses exactly the deadlines the reads would already refuse.
    function isExpired(uint256 deadline) internal view returns (bool) {
        return deadline != NO_DEADLINE && block.timestamp > deadline;
    }

    /// @notice Hashed so no witness value collides with NOT_NOMINATED; the (unreachable) zero hash
    ///         is remapped to 1 so the invariant holds without relying on "practically impossible".
    function nominationOf(uint256 witness) internal pure returns (uint256 value) {
        value = uint256(EfficientHashLib.hash(bytes32(witness)));
        if (value == NOT_NOMINATED) value = 1;
    }

    /// @notice Records the nomination for an (id, account) in transient storage
    function setNomination(uint256 id, address account, uint256 value) internal {
        bytes32 slot = EfficientHashLib.hash(
            NOMINATION_POSITION, bytes32(uint256(uint160(account))), bytes32(id)
        );
        assembly ("memory-safe") {
            tstore(slot, value)
        }
    }

    /// @notice The nomination recorded for an (id, account) in this transaction
    function nomination(uint256 id, address account) internal view returns (uint256 value) {
        bytes32 slot = EfficientHashLib.hash(
            NOMINATION_POSITION, bytes32(uint256(uint160(account))), bytes32(id)
        );
        assembly ("memory-safe") {
            value := tload(slot)
        }
    }
}
