// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import { PolicyConfig } from "@policies/claim/lib/ConfigLib.sol";
import {
    ParamRules,
    TokenInConfig,
    TargetConfig,
    TokenOutConfig,
    OpsRequirementConfig
} from "@policies/compact/types/DataTypes.sol";

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
    // TokenIn: per chainId (chainId = 0 for catch-all)
    // Only token + lockTag, no amounts
    mapping(
        ConfigId id
            => mapping(
            address msgSender
                => mapping(
                address userOpSender => mapping(uint256 chainId => TokenInConfig tokenInConfig)
            )
        )
    ) tokenInConfig;
    // Target: per targetChainId (targetChainId = 0 for catch-all)
    // Includes recipient + packed fillExpiry (uint128 min | uint128 max)
    mapping(
        ConfigId id
            => mapping(
            address msgSender
                => mapping(
                address userOpSender => mapping(uint256 targetChainId => TargetConfig targetConfig)
            )
        )
    ) targetConfig;
    // TokenOut: per targetChainId (targetChainId = 0 for catch-all)
    // Only token, no amounts
    mapping(
        ConfigId id
            => mapping(
            address msgSender
                => mapping(
                address userOpSender
                    => mapping(uint256 targetChainId => TokenOutConfig tokenOutConfig)
            )
        )
    ) tokenOutConfig;
    // Ops requirements: per chainId (chainId = 0 for catch-all)
    mapping(
        ConfigId id
            => mapping(
            address msgSender
                => mapping(
                address userOpSender
                    => mapping(uint256 chainId => OpsRequirementConfig opsRequirementConfig)
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
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @dev keccak256("smartsessions.policies.compact.storage.v1")
    bytes32 internal constant POLICY_STORAGE_POSITION =
        0xdcea712ce6c2213c29b40f80bf1e5d1b9d030a46b056c1cb82285d5245f55aed;

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
