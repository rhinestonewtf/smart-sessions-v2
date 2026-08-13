// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import { PinnedNonce } from "@policies/nonce/types/NoncePinDataTypes.sol";

/*//////////////////////////////////////////////////////////////
                         STORAGE LAYOUT
//////////////////////////////////////////////////////////////

Storage slot = keccak256(BASE_SLOT, multiplexer, configId, account)

Isolated per (multiplexer, configId, account), matching the layout the
IPolicy interface recommends and the claim policy family uses.

//////////////////////////////////////////////////////////////*/

/// @title Nonce Pin Storage Library
/// @author Rhinestone
/// @notice Namespaced storage for the pinned nonce
library NoncePinStorageLib {
    /// @dev keccak256("rhinestone.storage.NoncePinPolicy") - 1
    bytes32 internal constant STORAGE_POSITION =
        0x28ae8a7519be5377901d99ddf23b378cdcf388f17c49f598f0db470ae85e1a86;

    /// @notice Returns the pinned nonce slot for a configuration
    /// @param id The configuration ID
    /// @param account The account the configuration belongs to
    /// @param multiplexer The multiplexer that initialized the configuration
    /// @return $ Storage pointer to the pinned nonce
    function getStorage(
        ConfigId id,
        address account,
        address multiplexer
    )
        internal
        pure
        returns (PinnedNonce storage $)
    {
        bytes32 slot = calculateSlot(STORAGE_POSITION, id, account, multiplexer);
        // solhint-disable-next-line no-inline-assembly
        assembly {
            $.slot := slot
        }
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
