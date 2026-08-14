// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import { BridgeSession } from "@policies/bridge/types/BridgeSessionDataTypes.sol";

/*//////////////////////////////////////////////////////////////
                         STORAGE LAYOUT
//////////////////////////////////////////////////////////////

Storage slot = keccak256(BASE_SLOT, multiplexer, configId, account)

Isolated per (multiplexer, configId, account), matching the layout the IPolicy
interface recommends and the claim policy family uses.

//////////////////////////////////////////////////////////////*/

/// @title Bridge Session Storage Library
/// @author Rhinestone
/// @notice Namespaced storage for a bridge session
library BridgeSessionStorageLib {
    /// @dev keccak256("rhinestone.storage.BridgeSessionPolicy") - 1
    bytes32 internal constant STORAGE_POSITION =
        0x6de218e581d29ffd52900e6aa6e7e2401d998d61eb4a66b4f5a2d8233e1a1446;

    /// @notice Returns the bridge session slot for a configuration
    /// @param id The configuration ID
    /// @param account The account the configuration belongs to
    /// @param multiplexer The multiplexer that initialized the configuration
    /// @return $ Storage pointer to the bridge session
    function getStorage(
        ConfigId id,
        address account,
        address multiplexer
    )
        internal
        pure
        returns (BridgeSession storage $)
    {
        bytes32 slot = calculateSlot(STORAGE_POSITION, id, account, multiplexer);
        // solhint-disable-next-line no-inline-assembly
        assembly {
            $.slot := slot
        }
    }

    /// @notice The configuration ID to hand a settlement policy
    /// @dev A settlement policy is called BY this one, so its own storage keys on this policy's
    ///      address - a constant, identical whoever started the chain. That erases the separation
    ///      `multiplexer` provides one level up, where the caller varies. Folding the real
    ///      multiplexer in restores it: an init routed through a different caller derives a
    ///      different ID and lands somewhere the validation path never reads. See RHI-5829, which
    ///      is this same defect in the claim policy family.
    /// @dev Must be derived identically wherever a settlement policy is initialized or consulted.
    ///      A site that forgets fails closed - the policy reads an unwritten configuration
    /// @dev The layer and generation are folded in as well, so two layers never share one
    ///      settlement config and a re-initialization never inherits the previous one
    /// @param id The configuration ID of this policy
    /// @param multiplexer The multiplexer that called this policy, not this policy itself
    /// @param generation The session's current generation
    /// @param layer The settlement layer this configuration belongs to
    /// @return The configuration ID the settlement policy is keyed by
    function toLayerConfigId(
        ConfigId id,
        address multiplexer,
        uint256 generation,
        uint8 layer
    )
        internal
        pure
        returns (ConfigId)
    {
        return ConfigId.wrap(keccak256(abi.encode(id, multiplexer, generation, layer)));
    }

    /// @notice The key a layer's settlement policy is stored under
    /// @dev Keyed by generation so a re-initialization that drops a layer leaves the old entry
    ///      unreachable rather than live - a mapping cannot be enumerated to clear it
    /// @param generation The session's current generation
    /// @param layer The settlement layer
    /// @return The mapping key
    function toLayerKey(uint256 generation, uint8 layer) internal pure returns (uint256) {
        return (generation << 8) | layer;
    }

    /// @notice Calculates the storage slot for a given ConfigId, account, and multiplexer
    /// @param baseSlot The namespace base slot
    /// @param id The configuration ID
    /// @param account The account the configuration belongs to
    /// @param multiplexer The multiplexer that initialized the configuration
    /// @return slot The computed storage slot
    function calculateSlot(
        bytes32 baseSlot,
        ConfigId id,
        address account,
        address multiplexer
    )
        internal
        pure
        returns (bytes32 slot)
    {
        // solhint-disable-next-line no-inline-assembly
        assembly {
            let ptr := mload(0x40)
            mstore(0x00, baseSlot)
            mstore(0x20, multiplexer)
            mstore(0x40, id)
            mstore(0x60, account)
            slot := keccak256(0x00, 0x80)
            mstore(0x40, ptr)
            mstore(0x60, 0x00)
        }
    }
}
