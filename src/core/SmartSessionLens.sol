// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.28;

// Contracts
import { SmartSessionStorage } from "@core/SmartSessionStorage.sol";

// Interfaces
import { ISmartSessionLens } from "@interfaces/ISmartSessionLens.sol";

// Libraries
import { EnumerableSet } from "@smartsessions/utils/EnumerableSet4337.sol";
import { FlatBytesLib } from "@flatbytes/BytesLib.sol";
import { HashLib } from "@smartsessions/lib/HashLib.sol";
import { HashLibV2 } from "@lib/HashLibV2.sol";
import { IdLibV2 } from "@lib/IdLibV2.sol";
import { ConfigLib } from "@smartsessions/lib/ConfigLib.sol";
import { SignatureLib } from "@lib/SignatureLib.sol";

// Types
import {
    PermissionId,
    ActionId,
    SignerConf,
    ERC7739ContextHashes,
    ERC7579_MODULE_TYPE_VALIDATOR,
    EMPTY_PERMISSIONID
} from "@smartsessions/DataTypes.sol";
import {
    Session,
    SmartSessionEmissaryDisable,
    SmartSessionEmissaryConfig
} from "@types/DataTypes.sol";

/// @title SmartSessionLens
/// @notice Helper contract for reading SmartSession state and managing nonces
/// @dev Added to mitigate contract size limit, called via delegatecall from SmartSessionEmissary
///      fallback. This contract inherits SmartSessionStorage to ensure identical storage layout.
contract SmartSessionLens is SmartSessionStorage, ISmartSessionLens {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using EnumerableSet for *;
    using FlatBytesLib for *;
    using HashLib for *;
    using HashLibV2 for *;
    using IdLibV2 for *;
    using EnumerableSet for *;
    using ConfigLib for *;
    using SignatureLib for *;

    /*//////////////////////////////////////////////////////////////
                                  7579
    //////////////////////////////////////////////////////////////*/

    /// @notice Initialize the module with the given data
    /// @dev No-op for SmartSessionEmissary, sessions are enabled via setConfig
    function onInstall(bytes calldata) external { }

    /// @notice De-initialize the module
    /// @dev No-op for SmartSessionEmissary, sessions are disabled via removeConfig
    function onUninstall(bytes calldata) external { }

    /// @notice Check if the module is initialized for a specific smart account
    /// @param smartAccount The smart account address to check
    /// @return True if the module has any enabled sessions
    function isInitialized(address smartAccount) external view returns (bool) {
        return $enabledSessions.length({ account: smartAccount }) != 0;
    }

    /// @notice Check if the module type matches the validator type
    /// @param typeID The type ID to check
    /// @return True if the module type matches
    function isModuleType(uint256 typeID) external pure returns (bool) {
        return typeID == ERC7579_MODULE_TYPE_VALIDATOR;
    }

    /*//////////////////////////////////////////////////////////////
                                  NONCE
    //////////////////////////////////////////////////////////////*/

    /// @notice Get the current nonce for a given lock tag and sponsor
    /// @param sponsor The sponsor address
    /// @param lockTag The lock tag associated with the nonce
    /// @return The current nonce value
    function getNonce(address sponsor, bytes12 lockTag) external view returns (uint256) {
        return $emissaryNonce[sponsor][lockTag];
    }

    /// @notice Revoke the current nonce for a given lock tag, sponsor being the caller
    /// @param lockTag The lock tag associated with the nonce to be revoked
    function revokeNonce(bytes12 lockTag) external {
        uint256 nonce = ++$emissaryNonce[msg.sender][lockTag];
        emit NonceIterated(lockTag, msg.sender, nonce);
    }

    /*//////////////////////////////////////////////////////////////
                                DISABLE
    //////////////////////////////////////////////////////////////*/

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
        external
    {
        // Disable session
        _disableSessions({ account: account, disableData: disableData, config: config });
    }

    /// @notice Removes a session and all its associated policies from storage
    /// @dev Cleans up in order: ERC1271 → Action → Claim → ERC7739 → Validator → Session
    /// @param permissionId The unique identifier for the session to be removed
    /// @param account The account address associated with the session
    /// @param lockTag The lock tag used to identify the session
    function _removeSession(PermissionId permissionId, address account, bytes12 lockTag) internal {
        if (permissionId == EMPTY_PERMISSIONID) revert InvalidSession(permissionId);

        // Remove all ERC1271 policies for this session
        $erc1271Policies.policyList[permissionId].removeAll(account);

        // Remove all Action policies for this session
        uint256 actionLength = $actionPolicies.enabledActionIds[permissionId].length(account);
        for (uint256 i; i < actionLength; i++) {
            ActionId actionId = ActionId.wrap(
                $actionPolicies.enabledActionIds[permissionId].at({ account: account, index: i })
            );
            $actionPolicies.actionPolicies[actionId].policyList[permissionId].removeAll(account);
        }

        // removing all stored actionIds
        $actionPolicies.enabledActionIds[permissionId].removeAll(account);

        // Remove all claim policies for this session
        $claimPolicies[lockTag].policyList[permissionId].removeAll(account);

        // Remove the enabled erc7739 config for this session
        $enabledERC7739.removeAll({ permissionId: permissionId, smartAccount: account });

        // Disable the session validator
        $sessionValidators.disable({ permissionId: permissionId, smartAccount: account });

        // Remove the permissionId from enabled sessions
        $enabledSessions.remove({ account: account, value: PermissionId.unwrap(permissionId) });

        // Remove the lockTag from this permissionId
        $enabledLockTags[permissionId].remove({ account: account, value: bytes32(lockTag) });
    }

    /// @notice Disables sessions for an account after verifying required signatures
    /// @dev Verifies signatures then delegates to _removeSession for cleanup
    /// @param account The address of the account for which policies are being disabled
    /// @param disableData The data containing session disable information
    /// @param config The Smart Session Emissary configuration
    function _disableSessions(
        address account,
        SmartSessionEmissaryDisable calldata disableData,
        SmartSessionEmissaryConfig calldata config
    )
        internal
    {
        // Derive lockTag from allocator, scope, resetPeriod
        bytes12 lockTag = config.allocator.deriveLockTag(config.scope, config.resetPeriod);

        // Verify data expires after current block timestamp
        require(disableData.expires > block.timestamp, InvalidEmissaryDisableData());

        // Increment nonce to prevent replay attacks
        uint256 nonce = $emissaryNonce[account][lockTag]++;

        // Get the hash for the disable operation
        bytes32 hash = disableData.session
            .getAndVerifyDigest({
                permissionId: config.permissionId,
                account: account,
                nonce: nonce,
                expires: disableData.expires,
                lockTag: lockTag
            });

        // Verify the user and allocator signatures
        hash.verifySignatures({
            allocator: config.allocator,
            user: account,
            allocatorSignature: disableData.allocatorSig,
            userSignature: disableData.userSig,
            isInit: true // Disabling always requires both signatures if allocator is set
        });

        // Remove the session from the smart session config
        _removeSession({ permissionId: config.permissionId, account: account, lockTag: lockTag });

        // Emit event if the session is removed
        emit SmartSessionEmissaryConfigDisabled(account, config.permissionId, lockTag);
    }

    /*//////////////////////////////////////////////////////////////
                               PERMISSIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get the permission ID from a session
    /// @param session The session data
    /// @return permissionId The permission ID derived from the session
    function getPermissionId(Session calldata session)
        public
        pure
        returns (PermissionId permissionId)
    {
        permissionId = session.toPermissionId();
    }

    /// @notice Get all permission IDs for an account
    /// @param account The account address
    /// @return permissionIds Array of permission IDs
    function getPermissionIds(address account)
        external
        view
        returns (PermissionId[] memory permissionIds)
    {
        bytes32[] memory _permissionIds = $enabledSessions.values(account);
        assembly {
            permissionIds := _permissionIds
        }
    }

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
        returns (bool)
    {
        return
            $enabledSessions.contains({
                account: account, value: PermissionId.unwrap(permissionId)
            });
    }

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
        returns (bool)
    {
        return
            $enabledLockTags[permissionId].contains({ account: account, value: bytes32(lockTag) });
    }

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
        returns (address[] memory)
    {
        return $actionPolicies.actionPolicies[actionId].policyList[permissionId].values(account);
    }

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
        returns (bytes32[] memory)
    {
        return $actionPolicies.enabledActionIds[permissionId].values(account);
    }

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
        returns (bool)
    {
        return $actionPolicies.actionPolicies[actionId].policyList[permissionId].contains({
            account: account, value: policy
        });
    }

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
        returns (bool)
    {
        return $actionPolicies.enabledActionIds[permissionId].contains({
            account: account, value: ActionId.unwrap(actionId)
        });
    }

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
        returns (address[] memory)
    {
        return $claimPolicies[lockTag].policyList[permissionId].values(account);
    }

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
        returns (bool)
    {
        return $claimPolicies[lockTag].policyList[permissionId].contains({
            account: account, value: policy
        });
    }

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
        returns (address[] memory)
    {
        return $erc1271Policies.policyList[permissionId].values(account);
    }

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
        returns (bool)
    {
        return
            $erc1271Policies.policyList[permissionId].contains({ account: account, value: policy });
    }

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
        returns (ERC7739ContextHashes[] memory enabledERC7739ContentHashes)
    {
        uint256 length = $enabledERC7739.enabledDomainSeparators[permissionId].length(account);
        enabledERC7739ContentHashes = new ERC7739ContextHashes[](length);

        for (uint256 i; i < length; i++) {
            enabledERC7739ContentHashes[i].appDomainSeparator = $enabledERC7739.enabledDomainSeparators[permissionId].at({
                account: account, index: i
            });
            // solhint-disable-next-line max-line-length
            enabledERC7739ContentHashes[i].contentNameHashes = $enabledERC7739.enabledContentNames[permissionId][enabledERC7739ContentHashes[i].appDomainSeparator].values(
                account
            );
        }
    }

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
        returns (bool)
    {
        return $enabledERC7739.enabledContentNames[permissionId][appDomainSeparator].contains({
            account: account, value: content.hashERC7739Content()
        });
    }

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
        returns (address sessionValidator, bytes memory sessionValidatorData)
    {
        SignerConf storage $s = $sessionValidators[permissionId][account];
        sessionValidator = address($s.sessionValidator);
        sessionValidatorData = $s.config.load();
    }

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
        returns (bool)
    {
        return address($sessionValidators[permissionId][account].sessionValidator) != address(0);
    }

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
        Session calldata data,
        bytes12 lockTag,
        uint256 expires
    )
        external
        view
        returns (bytes32)
    {
        uint256 nonce = $emissaryNonce[account][lockTag];
        return
            data.sessionDigest({
                account: account, lockTag: lockTag, expires: expires, nonce: nonce
            });
    }
}
