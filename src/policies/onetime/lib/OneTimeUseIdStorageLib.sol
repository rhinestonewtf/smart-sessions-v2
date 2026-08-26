// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

import { ConfigId } from "@smartsessions/DataTypes.sol";

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

    /// @dev Zero id means "not configured"
    struct PinStorage {
        uint256 id;
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
        bytes32 slot = keccak256(abi.encode(PIN_POSITION, configId, multiplexer, account));
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
        bytes32 slot = keccak256(abi.encode(SPEND_POSITION, id, account));
        assembly {
            $.slot := slot
        }
    }

    /// @notice Hashed so no witness value collides with NOT_NOMINATED; the (unreachable) zero hash
    ///         is remapped to 1 so the invariant holds without relying on "practically impossible".
    function nominationOf(uint256 witness) internal pure returns (uint256 value) {
        value = uint256(keccak256(abi.encode(witness)));
        if (value == NOT_NOMINATED) value = 1;
    }

    /// @notice Records the nomination for an (id, account) in transient storage
    function setNomination(uint256 id, address account, uint256 value) internal {
        bytes32 slot = keccak256(abi.encode(NOMINATION_POSITION, account, id));
        assembly ("memory-safe") {
            tstore(slot, value)
        }
    }

    /// @notice The nomination recorded for an (id, account) in this transaction
    function nomination(uint256 id, address account) internal view returns (uint256 value) {
        bytes32 slot = keccak256(abi.encode(NOMINATION_POSITION, account, id));
        assembly ("memory-safe") {
            value := tload(slot)
        }
    }
}
