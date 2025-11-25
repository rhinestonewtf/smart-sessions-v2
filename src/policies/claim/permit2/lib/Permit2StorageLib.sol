// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Libraries
import { EnumerableSetLib } from "solady/utils/EnumerableSetLib.sol";
import { BaseStorageLib } from "@policies/claim/base/lib/BaseStorageLib.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";

// forgefmt: disable-start
/// @title Permit2 Storage Library
/// @author Rhinestone
/// @notice Diamond-storage pattern for Permit2-specific ClaimPolicy storage
/// @dev Permit2 tokenIn uses AddressSet (no lockTag, unlike Compact)
///
/// ┌────────────────────────────────────────────────────────────┐
/// │                 Permit2PolicyStorage Layout                │
/// │                                                            │
/// │  tokenInSet ─────► mapping(chainId => AddressSet)          │
/// │                    └─► Token addresses                     │
/// └────────────────────────────────────────────────────────────┘
// forgefmt: disable-end

struct Permit2PolicyStorage {
    /// @notice Whitelisted input tokens per chain
    /// @dev Uses AddressSet for token addresses
    ///      chainId = 0 is reserved for catch-all
    mapping(uint256 chainId => EnumerableSetLib.AddressSet tokenSet) tokenInSet;
}

library Permit2StorageLib {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using BaseStorageLib for bytes32;

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @dev keccak256("rhinestone.storage.Permit2ClaimPolicy") - 1
    bytes32 internal constant STORAGE_POSITION =
        0x4233f901f47f3db2f76e8bf26a95bb218080112509938f6f4b15576a90f7060c;

    /*//////////////////////////////////////////////////////////////
                            STORAGE ACCESS
    //////////////////////////////////////////////////////////////*/

    /// @notice Returns the storage pointer for Permit2PolicyStorage
    /// @param id ConfigId for the policy configuration
    /// @param account Account address for the policy configuration
    /// @return $ Storage pointer to the Permit2PolicyStorage struct
    function getStorage(
        ConfigId id,
        address account
    )
        internal
        pure
        returns (Permit2PolicyStorage storage $)
    {
        bytes32 slot = STORAGE_POSITION.calculateSlot(id, account);
        // solhint-disable-next-line no-inline-assembly\
        assembly {
            $.slot := slot
        }
    }
}

