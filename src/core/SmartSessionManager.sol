// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.28;

// Contracts
import { SmartSessionStorage } from "@core/SmartSessionStorage.sol";

// Libraries
import { EnumerableSet } from "@smartsessions/utils/EnumerableSet4337.sol";
import { ConfigLib } from "@smartsessions/lib/ConfigLib.sol";
import { IdLib } from "@smartsessions/lib/IdLib.sol";
import { IdLibV2 } from "@lib/IdLibV2.sol";
import { HashLibV2 } from "@lib/HashLibV2.sol";
import { PolicyLib } from "@smartsessions/lib/PolicyLib.sol";
import { ConfigLibV2 } from "@lib/ConfigLibV2.sol";
import { SignatureLib } from "@lib/SignatureLib.sol";
import { PolicyLibV2 } from "@lib/PolicyLibV2.sol";

// Interfaces
import { ISmartSessionEmissary } from "@interfaces/ISmartSessionEmissary.sol";

// Types
import {
    PermissionId,
    ActionId,
    SignerConf,
    EnumerableActionPolicy,
    PolicyType,
    EMPTY_PERMISSIONID,
    Policy,
    EnumerableERC7739Config,
    ERC7579_MODULE_TYPE_VALIDATOR
} from "@smartsessions/DataTypes.sol";
import {
    Session,
    SmartSessionEmissaryEnable,
    SmartSessionEmissaryConfig,
    DisableSession,
    NO_LOCKTAG
} from "@types/DataTypes.sol";

/// @title SmartSessionManager
/// @author Rhinestone
/// @notice Core session lifecycle management for the SmartSession Emissary system.
/// @dev Inherits storage layout from SmartSessionStorage for delegatecall compatibility.
abstract contract SmartSessionManager is SmartSessionStorage, ISmartSessionEmissary {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using EnumerableSet for *;
    using ConfigLib for *;
    using ConfigLibV2 for *;
    using IdLib for *;
    using IdLibV2 for *;
    using HashLibV2 for *;
    using PolicyLibV2 for *;
    using SignatureLib for *;

    /*//////////////////////////////////////////////////////////////
                           SESSION MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Enables a session for an account after verifying required signatures
    /// @dev Performs the following:
    ///      1. Increments nonce to prevent replay attacks
    ///      2. Verifies allocator and user signatures
    ///      3. Enables all associated policies (ERC7739, ERC1271, action, claim)
    ///      4. Configures the session validator
    /// @param account The address of the account for which policies are being enabled
    /// @param enableData The data containing session and policy information to be enabled
    /// @param config The Smart Session Emissary configuration
    function _enableSession(
        address account,
        SmartSessionEmissaryEnable calldata enableData,
        SmartSessionEmissaryConfig calldata config,
        bytes12 lockTag
    )
        internal
    {
        // Increment nonce to prevent replay attacks
        uint256 nonce = $emissaryNonce[account][lockTag]++;
        bytes32 hash = enableData.session
            .getAndVerifyDigest({
                account: account, nonce: nonce, expires: enableData.expires, lockTag: lockTag
            });

        // Check if the permissionId is already enabled for the account
        bool isInit = $enabledLockTags.contains({ account: account, value: bytes32(lockTag) });

        // Verify the user and allocator signatures
        hash.verifySignatures({
            allocator: config.allocator,
            user: account,
            allocatorSignature: enableData.allocatorSig,
            userSignature: enableData.userSig,
            isInit: !isInit
        });

        // Calculate the permissionId
        PermissionId permissionId = enableData.session.sessionToEnable.toPermissionId();

        // Ensure the permissionId matches the config
        require(permissionId == config.permissionId, InvalidPermissionId(config.permissionId));

        // Enable ERC7739 content
        $enabledERC7739.enable({
            contexts: enableData.session.sessionToEnable.erc7739Policies.allowedERC7739Content,
            permissionId: permissionId,
            account: account
        });

        // Enable ERC1271 policies
        $erc1271Policies.enable({
            policyType: PolicyType.ERC1271,
            permissionId: permissionId,
            configId: permissionId.toErc1271PolicyId().toConfigId(),
            policyDatas: enableData.session.sessionToEnable.erc7739Policies.erc1271Policies,
            account: account
        });

        // Enable action and claim policies only if lockTag is not NO_LOCKTAG
        if (lockTag != NO_LOCKTAG) {
            // Enable action policies
            $actionPolicies[lockTag].enable({
                permissionId: permissionId,
                actionPolicyDatas: enableData.session.sessionToEnable.actions,
                account: account
            });

            // Enable claim policies
            $claimPolicies[lockTag].enable({
                policyType: PolicyType.ERC1271,
                permissionId: permissionId,
                configId: permissionId.toErc1271PolicyId().toConfigId(),
                policyDatas: enableData.session.sessionToEnable.claimPolicies,
                account: account
            });

            // Add the lockTag to the enabled lockTags for the account
            $enabledLockTags.add({ account: account, value: bytes32(lockTag) });
        }

        // Enable mode can involve enabling ISessionValidator (new Permission)
        // or just adding policies (existing permission)
        // a) ISessionValidator is not set => enable ISessionValidator
        // b) ISessionValidator is set => just add policies (above)
        // Attention: if the same policy that has already been configured is added again,
        // the policy will be overwritten with the new configuration
        if (!_isISessionValidatorSet(permissionId, account)) {
            $sessionValidators.enable({
                permissionId: permissionId,
                sessionValidator: enableData.session.sessionToEnable.sessionValidator,
                sessionValidatorConfig: enableData.session.sessionToEnable.sessionValidatorInitData,
                account: account
            });
        }

        // Add to enabled sessions
        $enabledSessions.add({ account: account, value: PermissionId.unwrap(permissionId) });
    }

    /// @notice Disables sessions for an account after verifying required signatures
    /// @dev Verifies signatures then delegates to _removeSession for cleanup
    /// @param account The address of the account for which policies are being disabled
    /// @param disableData The data containing session and policy information to be disabled
    /// @param permissionId The unique identifier for the permission set
    /// @param lockTag The lock tag associated with the session
    /// @param expires The expiration timestamp for the disable signature
    /// @param allocator The address of the allocator for the session
    /// @param allocatorSig The signature from the allocator authorizing the disable
    /// @param userSig The signature from the user authorizing the session disable
    function _disableSessions(
        address account,
        DisableSession memory disableData,
        PermissionId permissionId,
        bytes12 lockTag,
        uint256 expires,
        address allocator,
        bytes calldata allocatorSig,
        bytes calldata userSig
    )
        internal
    {
        // Increment nonce to prevent replay attacks
        uint256 nonce = $emissaryNonce[account][lockTag]++;

        // Get the hash for the disable operation
        bytes32 hash = disableData.getAndVerifyDigest({
            permissionId: permissionId,
            account: account,
            nonce: nonce,
            expires: expires,
            lockTag: lockTag
        });

        // Verify the user and allocator signatures
        hash.verifySignatures({
            allocator: allocator,
            user: account,
            allocatorSignature: allocatorSig,
            userSignature: userSig,
            isInit: false
        });

        // Remove the session from the smart session config
        _removeSession({ permissionId: permissionId, account: account, lockTag: lockTag });
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
        uint256 actionLength =
            $actionPolicies[lockTag].enabledActionIds[permissionId].length(account);
        for (uint256 i; i < actionLength; i++) {
            ActionId actionId = ActionId.wrap(
                $actionPolicies[lockTag].enabledActionIds[permissionId].at({
                    account: account, index: i
                })
            );
            $actionPolicies[lockTag].actionPolicies[actionId].policyList[permissionId].removeAll(
                account
            );
        }

        // removing all stored actionIds
        $actionPolicies[lockTag].enabledActionIds[permissionId].removeAll(account);

        // Remove all claim policies for this session
        $claimPolicies[lockTag].policyList[permissionId].removeAll(account);

        // Remove the enabled erc7739 config for this session
        $enabledERC7739.removeAll({ permissionId: permissionId, smartAccount: account });

        // Disable the session validator
        $sessionValidators.disable({ permissionId: permissionId, smartAccount: account });

        // Remove the permissionId from enabled sessions
        $enabledSessions.remove({ account: account, value: PermissionId.unwrap(permissionId) });

        // Remove the lockTag from the enabled lockTag
        $enabledLockTags.remove({ account: account, value: bytes32(lockTag) });
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Checks if a session validator is configured for a permission
    /// @param permissionId The permission ID to check
    /// @param account The account address
    /// @return True if a session validator is set, false otherwise
    function _isISessionValidatorSet(
        PermissionId permissionId,
        address account
    )
        internal
        view
        returns (bool)
    {
        return address($sessionValidators[permissionId][account].sessionValidator) != address(0);
    }
}
