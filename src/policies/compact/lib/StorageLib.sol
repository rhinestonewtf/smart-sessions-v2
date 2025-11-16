// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Libraries
import { EnumerableSetLib } from "solady/utils/EnumerableSetLib.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import { PolicyConfig } from "@policies/claim/lib/ConfigLib.sol";
import { ParamRules } from "@policies/claim/types/DataTypes.sol";

/*//////////////////////////////////////////////////////////////
                             STRUCTS
//////////////////////////////////////////////////////////////*/

struct PolicyStorage {
    // Mapping to store the policy configuration bitmap for each account and config ID
    mapping(
        ConfigId id
            => mapping(
            address msgSender => mapping(address userOpSender => PolicyConfig conditionsBitmap)
        )
    ) policyConfig;
    // Arbiter validation
    mapping(
        ConfigId id
            => mapping(address msgSender => mapping(address userOpSender => address arbiter))
    ) arbiterConfig;
    // Claim expires validation (packed: uint128 min | uint128 max)
    mapping(
        ConfigId id
            => mapping(address msgSender => mapping(address userOpSender => uint256 packedExpires))
    ) claimExpiresConfig;
    // TokenIn: per chainId (chainId = 0 for catch-all)
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
    // Recipient: per targetChainId (targetChainId = 0 for catch-all)
    mapping(
        ConfigId id
            => mapping(
            address msgSender
                => mapping(
                address userOpSender => mapping(uint256 targetChainId => address recipient)
            )
        )
    ) recipientConfig;
    // FillExpiry: per targetChainId (targetChainId = 0 for catch-all)
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
    // TokenOut: per targetChainId (targetChainId = 0 for catch-all)
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
    // Ops requirements: per chainId (chainId = 0 for catch-all)
    // Packed: bool requireOriginOps (bit 0) | bool requireDestOps (bit 1)
    mapping(
        ConfigId id
            => mapping(
            address msgSender
                => mapping(
                address userOpSender => mapping(uint256 chainId => uint8 packedOpsRequirement)
            )
        )
    ) opsRequirementConfig;
    // Qualification params: per chainId (chainId = 0 for catch-all)
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
    ) qualificationConfig;
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
    bytes32 internal constant POLICY_STORAGE_POSITION = keccak256("claim.recipient.policy.storage");

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
