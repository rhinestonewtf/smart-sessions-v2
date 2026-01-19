// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.28;

// Libraries
import { EnumerableSet } from "@smartsessions/utils/EnumerableSet4337.sol";

// Types
import {
    PermissionId,
    SignerConf,
    EnumerableActionPolicy,
    Policy,
    EnumerableERC7739Config
} from "@smartsessions/DataTypes.sol";

/// @title SmartSessionStorage
/// @notice Storage layout for SmartSession contracts
/// @dev Inherited by SmartSessionManager and SmartSessionView to ensure identical storage layout
abstract contract SmartSessionStorage {
    /*//////////////////////////////////////////////////////////////
                                  NONCE
    //////////////////////////////////////////////////////////////*/

    /// @dev Mapping to store nonces for each sponsor and lockTag
    mapping(address sponsor => mapping(bytes12 lockTag => uint256 nonce)) internal $emissaryNonce;

    /*//////////////////////////////////////////////////////////////
                               PERMISSIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Set of enabled permission IDs per smart account
    EnumerableSet.Bytes32Set internal $enabledSessions;

    /// @notice Maps permission IDs and smart accounts to their corresponding lockTags
    mapping(PermissionId permissionId => mapping(address smartAccount => bytes12 lockTag)) internal
        $enabledLockTag;

    /*//////////////////////////////////////////////////////////////
                                POLICIES
    //////////////////////////////////////////////////////////////*/

    /// @notice Mapping of ERC1271 policies organized by permission IDs and smart account
    Policy internal $erc1271Policies;

    /// @notice Mapping of Action policies organized by permission IDs and smart account addresses
    EnumerableActionPolicy internal $actionPolicies;

    /// @notice Set of all enabled ERC7739 configurations for each smart account and permissionId
    EnumerableERC7739Config internal $enabledERC7739;

    /// @notice Mapping of lockTag to claim policies organized by permission IDs and smart account
    mapping(bytes12 lockTag => Policy claimPolicies) internal $claimPolicies;

    /*//////////////////////////////////////////////////////////////
                               VALIDATORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Mapping of session validators organized by permission IDs and smart account
    ///         addresses
    mapping(PermissionId permissionId => mapping(address smartAccount => SignerConf conf)) internal
        $sessionValidators;
}
