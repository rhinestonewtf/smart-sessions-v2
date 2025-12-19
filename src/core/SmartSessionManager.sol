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
import { ConfigLibV2 } from "@lib/ConfigLibV2.sol";
import { SignatureLib } from "@lib/SignatureLib.sol";
import { PolicyLibV2 } from "@lib/PolicyLibV2.sol";

// Interfaces
import { ISmartSessionEmissary } from "@interfaces/ISmartSessionEmissary.sol";

// Types
import {
    PermissionId,
    ActionId,
    PolicyType,
    EMPTY_PERMISSIONID
} from "@smartsessions/DataTypes.sol";
import {
    SmartSessionEmissaryEnable,
    SmartSessionEmissaryDisable,
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
    /// @param permissionId The permission ID associated with the session
    function _enableSession(
        address account,
        SmartSessionEmissaryEnable memory enableData,
        SmartSessionEmissaryConfig memory config,
        PermissionId permissionId
    )
        internal
    {
        // Derive lockTag from allocator, scope, resetPeriod
        bytes12 lockTag = config.allocator.deriveLockTag(config.scope, config.resetPeriod);

        // Verify data expires after current block timestamp
        require(enableData.expires > block.timestamp, InvalidEmissaryEnableData());

        // Increment nonce to prevent replay attacks
        uint256 nonce = $emissaryNonce[account][lockTag]++;
        bytes32 hash = enableData.session
            .getAndVerifyDigest({
                account: account, nonce: nonce, expires: enableData.expires, lockTag: lockTag
            });

        // Ensure the permissionId matches the config
        require(permissionId == config.permissionId, InvalidPermissionId(config.permissionId));

        // Check if this lockTag is already enabled for this permissionId.
        // - First enable (isInit=false): Only user signature required
        // - Subsequent enables (isInit=true): Both user AND allocator signatures required
        //
        // Note: When allocator == address(0) (no allocator / NO_LOCKTAG flow),
        // the allocator signature check is always skipped regardless of isInit.
        bool isInit =
            $enabledLockTags[permissionId].contains({ account: account, value: bytes32(lockTag) });

        // Verify the user and allocator signatures
        hash.verifySignatures({
            allocator: config.allocator,
            user: account,
            allocatorSignature: enableData.allocatorSig,
            userSignature: enableData.userSig,
            isInit: isInit
        });

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
            configId: permissionId.toErc1271PolicyId().toConfigId(account),
            policyDatas: enableData.session.sessionToEnable.erc7739Policies.erc1271Policies,
            account: account
        });

        // Enable action policies
        $actionPolicies.enable({
            permissionId: permissionId,
            actionPolicyDatas: enableData.session.sessionToEnable.actions,
            account: account
        });

        // Enable action and claim policies only if lockTag is not NO_LOCKTAG
        if (lockTag != NO_LOCKTAG) {
            // Enable claim policies
            $claimPolicies[lockTag].enable({
                policyType: PolicyType.ERC1271,
                permissionId: permissionId,
                configId: permissionId.toErc1271PolicyId().toConfigId(account),
                policyDatas: enableData.session.sessionToEnable.claimPolicies,
                account: account
            });
        }

        // Enable mode can involve enabling ISessionValidator (new Permission)
        // or just adding policies (existing permission)
        // a) ISessionValidator is not set => enable ISessionValidator
        // b) ISessionValidator is set => just add policies (above)
        // Attention: if the same policy that has already been configured is added again,
        // the policy will be overwritten with the new configuration
        if (address($sessionValidators[permissionId][account].sessionValidator) == address(0)) {
            $sessionValidators.enable({
                permissionId: permissionId,
                sessionValidator: enableData.session.sessionToEnable.sessionValidator,
                sessionValidatorConfig: enableData.session.sessionToEnable.sessionValidatorInitData,
                account: account
            });
        }

        // Add the permissionid to enabled sessions for the account
        $enabledSessions.add({ account: account, value: PermissionId.unwrap(permissionId) });

        // Add the lockTag to this permissionId
        $enabledLockTags[permissionId].add({ account: account, value: bytes32(lockTag) });

        // Emit event if the session is enabled
        emit SmartSessionEmissaryConfigEnabled(account, config.permissionId, lockTag);
    }
}
