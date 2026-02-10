// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

// Types
import { PermissionId, ActionId, ERC7739ContextHashes } from "@smartsessions/DataTypes.sol";
import {
    Session,
    SmartSessionEmissaryConfig,
    SmartSessionEmissaryDisable,
    SmartSessionEmissaryEnable
} from "@types/DataTypes.sol";

/// @title ISmartSessionLens
/// @notice Interface for SmartSessionLens - helper contract for reading SmartSession state
interface ISmartSessionLens {
    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown when the Emissary disable data is not valid
    error InvalidEmissaryDisableData();

    /// @notice Thrown when the session is not valid
    error InvalidSession(PermissionId permissionId);

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when the nonce is incremented
    event NonceIterated(bytes12 lockTag, address indexed account, uint256 nonce);

    /// @notice Emitted when a Smart Session Emissary configuration is disabled for an account.
    /// @param account The address of the account for which the configuration was disabled.
    /// @param permissionId The permission ID associated with the Smart Session.
    /// @param lockTag The lock tag derived from the allocator, scope, and reset period.
    event SmartSessionEmissaryConfigDisabled(
        address indexed account, PermissionId permissionId, bytes12 indexed lockTag
    );

    /*//////////////////////////////////////////////////////////////
                                  7579
    //////////////////////////////////////////////////////////////*/

    /// @notice Initialize the module with the given data
    function onInstall(bytes calldata) external;

    /// @notice De-initialize the module
    function onUninstall(bytes calldata) external;

    /// @notice Check if the module is initialized for a specific smart account
    /// @param smartAccount The smart account address to check
    /// @return True if the module has any enabled sessions
    function isInitialized(address smartAccount) external view returns (bool);

    /// @notice Check if the module type matches the validator type
    /// @param typeID The type ID to check
    /// @return True if the module type matches
    function isModuleType(uint256 typeID) external pure returns (bool);

    /*//////////////////////////////////////////////////////////////
                                  NONCE
    //////////////////////////////////////////////////////////////*/

    /// @notice Get the current nonce for a given lock tag and sponsor
    /// @param sponsor The sponsor address
    /// @param lockTag The lock tag associated with the nonce
    /// @return The current nonce value
    function getNonce(address sponsor, bytes12 lockTag) external view returns (uint256);

    /// @notice Revoke the current nonce for a given lock tag, sponsor being the caller
    /// @param lockTag The lock tag associated with the nonce to be revoked
    function revokeNonce(bytes12 lockTag) external;

    /*//////////////////////////////////////////////////////////////
                                 CONFIG
    //////////////////////////////////////////////////////////////*/

    /// @notice Sets the Smart Session Emissary configuration for a specific account.
    /// @param account The address of the account for which the configuration is being set.
    /// @param config The Smart Session Emissary configuration.
    /// @param enable The Smart Session Emissary enable data.
    function setConfig(
        address account,
        SmartSessionEmissaryConfig calldata config,
        SmartSessionEmissaryEnable calldata enable
    )
        external;

    /// @notice Removes a Smart Session Emissary configuration for a specific account
    /// @param account The address of the account for which the configuration is being removed
    /// @param config The Smart Session Emissary configuration to be removed
    /// @param disableData The disable data containing the allocatorSignature, user signature,
    ///                    disable session data, and expiration time
    function removeConfig(
        address account,
        SmartSessionEmissaryConfig calldata config,
        SmartSessionEmissaryDisable calldata disableData
    )
        external;
    /*//////////////////////////////////////////////////////////////
                               PERMISSIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get the permission ID from a session
    /// @param session The session data
    /// @return permissionId The permission ID derived from the session
    function getPermissionId(Session calldata session)
        external
        pure
        returns (PermissionId permissionId);

    /// @notice Get all permission IDs for an account
    /// @param account The account address
    /// @return permissionIds Array of permission IDs
    function getPermissionIds(address account)
        external
        view
        returns (PermissionId[] memory permissionIds);

    /// @notice Check if a permission ID is enabled for an account
    /// @param account The account address
    /// @param permissionId The permission ID
    /// @return True if the permission is enabled
    function isPermissionEnabled(
        address account,
        PermissionId permissionId
    )
        external
        view
        returns (bool);

    /// @notice Check if a lockTag is enabled for an account
    /// @param account The account address
    /// @param permissionId The permission ID associated with the lockTag
    /// @param lockTag The lock tag
    /// @return True if the lockTag is enabled
    function isLockTagEnabled(
        address account,
        PermissionId permissionId,
        bytes12 lockTag
    )
        external
        view
        returns (bool);

    /*//////////////////////////////////////////////////////////////
                             ACTION POLICIES
    //////////////////////////////////////////////////////////////*/

    /// @notice Get the action policies for a specific action ID
    /// @param account The account address
    /// @param permissionId The permission ID
    /// @param actionId The action ID
    /// @return Array of policy addresses
    function getActionPolicies(
        address account,
        PermissionId permissionId,
        ActionId actionId
    )
        external
        view
        returns (address[] memory);

    /// @notice Get all enabled actions for an account
    /// @param account The account address
    /// @param permissionId The permission ID
    /// @return Array of enabled action IDs as bytes32
    function getEnabledActions(
        address account,
        PermissionId permissionId
    )
        external
        view
        returns (bytes32[] memory);

    /// @notice Check if a specific action policy is enabled
    /// @param account The account address
    /// @param permissionId The permission ID
    /// @param actionId The action ID
    /// @param policy The policy address to check
    /// @return True if the policy is enabled
    function isActionPolicyEnabled(
        address account,
        PermissionId permissionId,
        ActionId actionId,
        address policy
    )
        external
        view
        returns (bool);

    /// @notice Check if an action ID is enabled
    /// @param account The account address
    /// @param permissionId The permission ID
    /// @param actionId The action ID
    /// @return True if the action ID is enabled
    function isActionIdEnabled(
        address account,
        PermissionId permissionId,
        ActionId actionId
    )
        external
        view
        returns (bool);

    /*//////////////////////////////////////////////////////////////
                             CLAIM POLICIES
    //////////////////////////////////////////////////////////////*/

    /// @notice Get the claim policies for a specific permission ID and lock tag
    /// @param account The account address
    /// @param permissionId The permission ID
    /// @param lockTag The associated lock tag
    /// @return Array of claim policy addresses
    function getClaimPolicies(
        address account,
        PermissionId permissionId,
        bytes12 lockTag
    )
        external
        view
        returns (address[] memory);

    /// @notice Check if a specific claim policy is enabled
    /// @param account The account address
    /// @param permissionId The permission ID
    /// @param lockTag The associated lock tag
    /// @param policy The policy address to check
    /// @return True if the policy is enabled
    function isClaimPolicyEnabled(
        address account,
        PermissionId permissionId,
        bytes12 lockTag,
        address policy
    )
        external
        view
        returns (bool);

    /*//////////////////////////////////////////////////////////////
                            ERC1271 POLICIES
    //////////////////////////////////////////////////////////////*/

    /// @notice Get the ERC1271 policies for a specific permission ID
    /// @param account The account address
    /// @param permissionId The permission ID
    /// @return Array of ERC1271 policy addresses
    function getERC1271Policies(
        address account,
        PermissionId permissionId
    )
        external
        view
        returns (address[] memory);

    /// @notice Check if a specific ERC1271 policy is enabled
    /// @param account The account address
    /// @param permissionId The permission ID
    /// @param policy The policy address to check
    /// @return True if the policy is enabled
    function isERC1271PolicyEnabled(
        address account,
        PermissionId permissionId,
        address policy
    )
        external
        view
        returns (bool);

    /*//////////////////////////////////////////////////////////////
                               ERC7739
    //////////////////////////////////////////////////////////////*/

    /// @notice Get all enabled ERC7739 content for an account and permission
    /// @param account The account address
    /// @param permissionId The permission ID
    /// @return enabledERC7739ContentHashes Array of ERC7739 context hashes
    function getEnabledERC7739Content(
        address account,
        PermissionId permissionId
    )
        external
        view
        returns (ERC7739ContextHashes[] memory enabledERC7739ContentHashes);

    /// @notice Check if a specific ERC7739 content is enabled
    /// @param account The account address
    /// @param permissionId The permission ID
    /// @param appDomainSeparator The app domain separator
    /// @param content The content string to check
    /// @return True if the content is enabled
    function isERC7739ContentEnabled(
        address account,
        PermissionId permissionId,
        bytes32 appDomainSeparator,
        string calldata content
    )
        external
        view
        returns (bool);

    /*//////////////////////////////////////////////////////////////
                               VALIDATORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get the session validator and its configuration
    /// @param account The account address
    /// @param permissionId The permission ID
    /// @return sessionValidator The address of the session validator
    /// @return sessionValidatorData The session validator configuration data
    function getSessionValidatorAndConfig(
        address account,
        PermissionId permissionId
    )
        external
        view
        returns (address sessionValidator, bytes memory sessionValidatorData);

    /// @notice Check if a session validator is set for a permission
    /// @param account The account address
    /// @param permissionId The permission ID
    /// @return True if a session validator is set
    function isSessionValidatorSet(
        address account,
        PermissionId permissionId
    )
        external
        view
        returns (bool);

    /*//////////////////////////////////////////////////////////////
                                SESSION
    //////////////////////////////////////////////////////////////*/

    /// @notice Get the session digest for verification
    /// @param account The account address
    /// @param lockTag The lock tag used to identify the session
    /// @param data The session data
    /// @param expires The expiration timestamp for the session
    /// @return The session digest
    function getSessionDigest(
        address account,
        Session memory data,
        bytes12 lockTag,
        uint256 expires
    )
        external
        view
        returns (bytes32);
}
