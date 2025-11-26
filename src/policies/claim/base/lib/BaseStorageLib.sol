// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Libraries
import { EnumerableSetLib } from "solady/utils/EnumerableSetLib.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import {
    QualificationRulesStorage,
    PolicyConfig
} from "@policies/claim/base/types/BaseDataTypes.sol";

/*//////////////////////////////////////////////////////////////
                         STORAGE LAYOUT
//////////////////////////////////////////////////////////////

The BaseClaimPolicy uses a storage pattern with unique
slot calculation per (configId, account) pair.

Storage slot = keccak256(BASE_SLOT, configId, account)

This provides:
• Isolated storage per configuration
• Per-account storage without nested mappings
• Gas-efficient access patterns

┌─────────────────────────────────────────────────────────────┐
│                    BasePolicyStorage Layout                 │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  modeConfig ─────────► PolicyConfig (uint32)                │
│                                                             │
│  arbiterConfig ──────► AddressSet (multiple arbiters)       │
│                                                             │
│  expiryConfig ───────► uint256 (packed min|max)             │
│                                                             │
│  recipientConfig ────► mapping(chainId => address)          │
│                                                             │
│  fillExpiryConfig ───► mapping(chainId => uint256)          │
│                                                             │
│  tokenOutSet ────────► mapping(chainId => AddressSet)       │
│                                                             │
│  originOpsConfig ────► mapping(chainId => bool)             │
│                                                             │
│  destOpsConfig ──────► mapping(chainId => bool)             │
│                                                             │
│  qualificationConfig ► mapping(chainId => arbiter => Rules) │
│                                                             │
│  subPolicies ────────► mapping(fieldId => address)          │
│                                                             │
└─────────────────────────────────────────────────────────────┘

//////////////////////////////////////////////////////////////*/

struct BasePolicyStorage {
    /*//////////////////////////////////////////////////////////////
                           MODE CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Mode configuration bitmap (2 bits per field, 9 fields)
    /// @dev See DataTypes.sol for field layout diagram
    ///
    /// Access: modeConfig[configId][account] => PolicyConfig
    PolicyConfig modeConfig;

    /*//////////////////////////////////////////////////////////////
                          SUB-POLICY DELEGATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Sub-policy contract addresses per field
    /// @dev When a field's mode is MODE_CHECK_SUBPOLICY, validation
    ///      is delegated to the policy stored here
    ///
    /// Access: subPolicies[configId][account][fieldId] => address
    mapping(uint8 fieldId => address policy) subPolicies;

    /*//////////////////////////////////////////////////////////////
                         ARBITER CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Required arbiter address (single value, not per-chain)
    /// @dev The arbiter is the entity that settles claims
    ///
    /// Access: arbiterConfig[configId][account] => AddressSet
    EnumerableSetLib.AddressSet arbiterConfig;

    /*//////////////////////////////////////////////////////////////
                          EXPIRY CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Claim expiry bounds (claimExpires for Compact, deadline for Permit2)
    /// @dev Packed format: lower 128 bits = min, upper 128 bits = max
    ///
    /// ┌────────────────────┬────────────────────┐
    /// │   max (uint128)    │   min (uint128)    │
    /// │   bits [255:128]   │   bits [127:0]     │
    /// └────────────────────┴────────────────────┘
    ///
    /// Access: expiryConfig[configId][account] => (packed min|max as uint128|uint128)
    uint256 expiryConfig;

    /*//////////////////////////////////////////////////////////////
                        RECIPIENT CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Required recipient per target chain
    /// @dev chainId = 0 is reserved for catch-all (MODE_CHECK_CATCHALL)
    ///
    /// Access: recipientConfig[configId][account][chainId] => recipient
    mapping(uint256 chainId => address recipient) recipientConfig;

    /*//////////////////////////////////////////////////////////////
                       FILL EXPIRY CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Fill expiry bounds per target chain
    /// @dev Packed format: lower 128 bits = min, upper 128 bits = max
    ///      chainId = 0 is reserved for catch-all
    ///
    /// Access: fillExpiryConfig[configId][account][chainId] => packed
    mapping(uint256 chainId => uint256 packedFillExpiry) fillExpiryConfig;

    /*//////////////////////////////////////////////////////////////
                        TOKEN IN CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /// @notice TokenIn whitelist per chain
    /// @dev Compact: Bytes32Set where we store packed bytes32(token+lockTag)
    /// @dev Permit2: Bytes32Set where we store bytes32(bytes20(token))
    ///      chainId = 0 is reserved for catch-all (MODE_CHECK_CATCHALL)
    ///
    /// Access: tokenInSet[configId][account][chainId] => Bytes32Set
    mapping(uint256 chainId => EnumerableSetLib.Bytes32Set tokenSet) tokenInSet;

    /*//////////////////////////////////////////////////////////////
                        TOKEN OUT CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Whitelisted output tokens per target chain
    /// @dev Uses EnumerableSetLib for efficient membership checks
    ///      chainId = 0 is reserved for catch-all
    ///
    /// Access: tokenOutSet[configId][account][chainId] => AddressSet
    mapping(uint256 chainId => EnumerableSetLib.AddressSet tokenSet) tokenOutSet;

    /*//////////////////////////////////////////////////////////////
                       ORIGIN OPS CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Origin operations requirement per chain
    /// @dev If true, the originOps hash must NOT equal NO_OPS
    ///      chainId = 0 is reserved for catch-all
    ///
    /// Access: originOpsConfig[configId][account][chainId] => required
    mapping(uint256 chainId => bool requireOriginOps) originOpsConfig;

    /*//////////////////////////////////////////////////////////////
                        DEST OPS CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Destination operations requirement per target chain
    /// @dev If true, the destOps hash must NOT equal NO_OPS
    ///      chainId = 0 is reserved for catch-all
    ///
    /// Access: destOpsConfig[configId][account][chainId] => required
    mapping(uint256 chainId => bool requireDestOps) destOpsConfig;

    /*//////////////////////////////////////////////////////////////
                      QUALIFICATION CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Qualification parameter rules per chain and arbiter
    /// @dev Qualification validation is arbiter-specific because different
    ///      arbiters may require different qualification data formats
    ///      chainId = 0 is reserved for catch-all
    ///
    /// Access: qualificationConfig[configId][account][chainId][arbiter] => rules
    mapping(
        uint256 chainId => mapping(address arbiter => QualificationRulesStorage qualificationRules)
    ) qualificationConfig;
}

/// @title Base Storage Library
/// @notice Diamond-storage pattern for shared ClaimPolicy storage
/// @dev Both CompactClaimPolicy and Permit2ClaimPolicy use this for shared fields
library BaseStorageLib {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using EnumerableSetLib for EnumerableSetLib.AddressSet;

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @dev keccak256("rhinestone.storage.BaseClaimPolicy") - 1
    bytes32 internal constant STORAGE_POSITION =
        0xd29377fc0db06555c0d0684662ad4cb507472ae21c689f22e192cb1a507e2989;

    /*//////////////////////////////////////////////////////////////
                            STORAGE ACCESS
    //////////////////////////////////////////////////////////////*/

    /// @notice Returns the storage pointer for BasePolicyStorage
    /// @param id ConfigId for the policy configuration
    /// @param account Account address for the policy configuration
    /// @return $ Storage pointer to the BasePolicyStorage struct
    function getStorage(
        ConfigId id,
        address account
    )
        internal
        pure
        returns (BasePolicyStorage storage $)
    {
        // Calculate the unique storage slot and cast to the storage struct
        bytes32 slot = calculateSlot(STORAGE_POSITION, id, account);
        // solhint-disable-next-line no-inline-assembly
        assembly {
            $.slot := slot
        }
    }

    /*//////////////////////////////////////////////////////////////
                            SLOT CALCULATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Calculates the storage slot for a given ConfigId and account
    function calculateSlot(
        bytes32 baseSlot,
        ConfigId id,
        address account
    )
        internal
        pure
        returns (bytes32 slot)
    {
        // solhint-disable-next-line no-inline-assembly
        assembly {
            // Get the free memory pointer
            let ptr := mload(0x40)
            // Store baseSlot,id,account
            mstore(0x00, baseSlot)
            mstore(0x20, id)
            mstore(0x40, account)
            // Compute keccak256 hash of the 96 bytes from 0x00 to 0x60
            slot := keccak256(0x00, 0x60)
            // Restore the free memory pointer
            mstore(0x40, ptr)
        }
    }
}
