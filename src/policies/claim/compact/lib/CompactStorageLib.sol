// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Libraries
import { EnumerableSetLib } from "solady/utils/EnumerableSetLib.sol";
import { BaseStorageLib } from "@policies/claim/base/lib/BaseStorageLib.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";

/*//////////////////////////////////////////////////////////////
                    COMPACT STORAGE LAYOUT
//////////////////////////////////////////////////////////////

Compact-specific storage for tokenIn with lockTag support.
This storage is separate from BasePolicyStorage.

The tokenIn set stores packed bytes32 values:
┌────────────────────────────────────────────────────────────┐
│              Packed bytes32 Value                          │
│  ┌────────────────────────┬────────────────────────────┐   │
│  │  token (160 bits)      │  lockTag (96 bits)         │   │
│  │  bits [159:0]          │  bits [255:160]            │   │
│  └────────────────────────┴────────────────────────────┘   │
└────────────────────────────────────────────────────────────┘

Storage is accessed via:
  tokenInSet[configId][account][chainId]

//////////////////////////////////////////////////////////////*/

/// @notice Compact-specific policy storage (tokenIn only)
/// @dev Separate from BasePolicyStorage to maintain clean separation
struct CompactPolicyStorage {
    /// @notice TokenIn whitelist per chain (packed token+lockTag)
    /// @dev Uses Bytes32Set because we store packed bytes32 values
    ///      chainId = 0 is reserved for catch-all (MODE_CHECK_CATCHALL)
    ///
    /// Access: tokenInSet[configId][account][chainId] => Bytes32Set
    mapping(uint256 chainId => EnumerableSetLib.Bytes32Set tokenSet) tokenInSet;
}

/// @title Compact Storage Library
/// @author Rhinestone
/// @notice Diamond-storage pattern for Compact-specific tokenIn storage
/// @dev Used alongside BaseStorageLib for the CompactClaimPolicy
library CompactStorageLib {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;
    using BaseStorageLib for bytes32;

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @dev keccak256("rhinestone.storage.CompactClaimPolicy.TokenIn") - 1
    bytes32 internal constant STORAGE_POSITION =
        0xf0dcbcf8a06e47ed89debe6feb3cdb0be5908cf07acf39213a9591748f911217;

    /*//////////////////////////////////////////////////////////////
                            STORAGE ACCESS
    //////////////////////////////////////////////////////////////*/

    /// @notice Returns the storage pointer for CompactPolicyStorage
    /// @param id ConfigId for the policy configuration
    /// @param account Account address for the policy configuration
    /// @return $ Storage pointer to the BasePolicyStorage struct
    function getStorage(
        ConfigId id,
        address account
    )
        internal
        pure
        returns (CompactPolicyStorage storage $)
    {
        bytes32 slot = STORAGE_POSITION.calculateSlot(id, account);
        // solhint-disable-next-line no-inline-assembly\
        assembly {
            $.slot := slot
        }
    }
}
