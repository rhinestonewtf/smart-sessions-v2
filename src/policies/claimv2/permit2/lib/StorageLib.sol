// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Libraries
import { EnumerableSetLib } from "solady/utils/EnumerableSetLib.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import { ParamRules } from "@policies/claimv2/compact/types/DataTypes.sol";

/*//////////////////////////////////////////////////////////////
                             STRUCTS
//////////////////////////////////////////////////////////////*/

struct PolicyStorage {
    // Mode configuration: 2 bits per field (9 fields = 18 bits)
    mapping(
        ConfigId id
            => mapping(address msgSender => mapping(address userOpSender => uint32 modeConfig))
    ) modeConfig;

    // Arbiter validation
    mapping(
        ConfigId id
            => mapping(address msgSender => mapping(address userOpSender => address arbiter))
    ) arbiterConfig;

    // Deadline bounds (min/max packed into uint256)
    mapping(
        ConfigId id => mapping(address msgSender => mapping(address userOpSender => uint256 packed))
    ) deadlineConfig;

    // TokenIn: per chainId
    mapping(
        ConfigId id
            => mapping(
            address msgSender
                => mapping(
                address userOpSender => mapping(uint256 chainId => EnumerableSetLib.AddressSet)
            )
        )
    ) tokenInSet;

    // Recipient per target chain
    mapping(
        ConfigId id
            => mapping(
            address msgSender
                => mapping(
                address userOpSender => mapping(uint256 targetChainId => address recipient)
            )
        )
    ) recipientConfig;

    // FillExpiry bounds per target chain (min/max packed)
    mapping(
        ConfigId id
            => mapping(
            address msgSender
                => mapping(address userOpSender => mapping(uint256 targetChainId => uint256 packed))
        )
    ) fillExpiryConfig;

    // TokenOut per target chain
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

    // Origin ops requirement per chain
    mapping(
        ConfigId id
            => mapping(
            address msgSender
                => mapping(
                address userOpSender => mapping(uint256 chainId => bool requireOriginOps)
            )
        )
    ) originOpsConfig;

    // Dest ops requirement per target chain
    mapping(
        ConfigId id
            => mapping(
            address msgSender
                => mapping(
                address userOpSender => mapping(uint256 targetChainId => bool requireDestOps)
            )
        )
    ) destOpsConfig;

    // Qualification rules per chain and arbiter
    mapping(
        ConfigId id
            => mapping(
            address msgSender
                => mapping(
                address userOpSender
                    => mapping(uint256 chainId => mapping(address arbiter => ParamRules))
            )
        )
    ) qualificationConfig;

    // Sub-policies per field
    mapping(
        ConfigId id
            => mapping(
            address msgSender
                => mapping(address userOpSender => mapping(uint8 fieldId => address policy))
        )
    ) subPolicies;
}

/// @title Permit2 Storage Library
/// @notice Library for managing storage of Permit2ClaimPolicy data
library Permit2StorageLib {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using EnumerableSetLib for EnumerableSetLib.AddressSet;

    /*//////////////////////////////////////////////////////////////
                                GETTERS
    //////////////////////////////////////////////////////////////*/

    /// @dev Storage slot: keccak256("rhinestone.storage.Permit2ClaimPolicy") - 1
    bytes32 private constant POLICY_STORAGE_LOCATION =
        0x4233f901f47f3db2f76e8bf26a95bb218080112509938f6f4b15576a90f7060c;

    function getPolicyStorage() internal pure returns (PolicyStorage storage $) {
        assembly {
            $.slot := POLICY_STORAGE_LOCATION
        }
    }
}
