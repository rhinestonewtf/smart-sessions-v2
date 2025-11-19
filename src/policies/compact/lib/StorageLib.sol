// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Libraries
import { EnumerableSetLib } from "solady/utils/EnumerableSetLib.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import { ParamRules } from "@policies/compact/types/DataTypes.sol";

/*//////////////////////////////////////////////////////////////
                             STRUCTS
//////////////////////////////////////////////////////////////*/

struct PolicyStorage {
    // ========== CONFIG BITMAP ==========
    // 2 bits per field (9 fields = 18 bits)
    // Bits [1:0]   - Arbiter mode
    // Bits [3:2]   - ClaimExpires mode
    // Bits [5:4]   - TokenIn mode
    // Bits [7:6]   - Recipient mode
    // Bits [9:8]   - FillExpiry mode
    // Bits [11:10] - TokenOut mode
    // Bits [13:12] - OriginOps mode
    // Bits [15:14] - DestOps mode
    // Bits [17:16] - Qualification mode
    mapping(
        ConfigId id
            => mapping(address msgSender => mapping(address userOpSender => uint32 modeConfig))
    ) modeConfig;

    // =========== SUB-POLICY CONFIGS ==========

    mapping(
        ConfigId id
            => mapping(
            address msgSender
                => mapping(address userOpSender => mapping(uint8 fieldId => address policy))
        )
    ) subPolicies;

    // ========== STORAGE-BASED CONFIGS ==========

    // Arbiter validation (single value, not per chain)
    mapping(
        ConfigId id
            => mapping(address msgSender => mapping(address userOpSender => address arbiter))
    ) arbiterConfig;

    // Claim expires validation (packed: uint128 min | uint128 max)
    mapping(
        ConfigId id
            => mapping(address msgSender => mapping(address userOpSender => uint256 packedExpires))
    ) claimExpiresConfig;

    // TokenIn: per chainId (chainId = 0 for catch-all if mode = MODE_CHECK_CATCHALL)
    // EnumerableSet of packed configs: address (20 bytes) + lockTag (12 bytes) = bytes32
    mapping(
        ConfigId id
            => mapping(
            address msgSender
                => mapping(
                address userOpSender => mapping(uint256 chainId => EnumerableSetLib.Bytes32Set)
            )
        )
    ) tokenInSet;

    // Recipient: per targetChainId (targetChainId = 0 for catch-all if mode = MODE_CHECK_CATCHALL)
    mapping(
        ConfigId id
            => mapping(
            address msgSender
                => mapping(
                address userOpSender => mapping(uint256 targetChainId => address recipient)
            )
        )
    ) recipientConfig;

    // FillExpiry: per targetChainId (targetChainId = 0 for catch-all if mode = MODE_CHECK_CATCHALL)
    // Packed: uint128 min | uint128 max
    mapping(
        ConfigId id
            => mapping(
            address msgSender
                => mapping(
                address userOpSender => mapping(uint256 targetChainId => uint256 packedFillExpiry)
            )
        )
    ) fillExpiryConfig;

    // TokenOut: per targetChainId (targetChainId = 0 for catch-all if mode = MODE_CHECK_CATCHALL)
    // EnumerableSet of addresses
    mapping(
        ConfigId id
            => mapping(
            address msgSender
                => mapping(
                address userOpSender
                    => mapping(uint256 targetChainId => EnumerableSetLib.AddressSet)
            )
        )
    ) tokenOutSet;

    // OriginOps requirements: per chainId (chainId = 0 for catch-all if mode = MODE_CHECK_CATCHALL)
    // Just a bool: true = must have non-empty originOps
    mapping(
        ConfigId id
            => mapping(
            address msgSender
                => mapping(
                address userOpSender => mapping(uint256 chainId => bool requireOriginOps)
            )
        )
    ) originOpsConfig;

    // DestOps requirements: per targetChainId (targetChainId = 0 for catch-all if mode =
    // MODE_CHECK_CATCHALL) Just a bool: true = must have non-empty destOps
    mapping(
        ConfigId id
            => mapping(
            address msgSender
                => mapping(
                address userOpSender => mapping(uint256 targetChainId => bool requireDestOps)
            )
        )
    ) destOpsConfig;

    // Qualification params: per chainId (chainId = 0 for catch-all if mode = MODE_CHECK_CATCHALL)
    mapping(
        ConfigId id
            => mapping(
            address msgSender
                => mapping(
                address userOpSender
                    => mapping(
                    uint256 chainId
                        => mapping(bytes32 qualificationTypehash => ParamRules qualificationConfig)
                )
            )
        )
    ) qualificationConfig; // TODO: Do we need this per qualificationTypehash?
}

/// @title Storage Library
/// @notice Library for managing storage of claim recipient data
library StorageLib {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;
    using EnumerableSetLib for EnumerableSetLib.AddressSet;

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    // TODO: Hardcode and truncate this
    bytes32 internal constant POLICY_STORAGE_POSITION = keccak256("compact.claim.policy.storage");

    /*//////////////////////////////////////////////////////////////
                               STORAGE ACCESS
    //////////////////////////////////////////////////////////////*/

    /// @notice Returns the storage slot for the PolicyStorage struct
    function getPolicyStorage() internal pure returns (PolicyStorage storage ps) {
        bytes32 position = POLICY_STORAGE_POSITION;
        assembly {
            ps.slot := position
        }
    }
}
