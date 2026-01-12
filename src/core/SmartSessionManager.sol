// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.28;

// Contracts
import { SmartSessionStorage } from "@core/SmartSessionStorage.sol";
import { ReentrancyGuardTransient } from "solady/utils/ReentrancyGuardTransient.sol";

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
    Session,
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
abstract contract SmartSessionManager is SmartSessionStorage, ReentrancyGuardTransient {
    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown when a permission ID is not valid
    error InvalidPermissionId(PermissionId permissionId);

    /// @notice Thrown when the Emissary enable data is not valid
    error InvalidEmissaryEnableData();

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when a Smart Session Emissary configuration is successfully set for an
    ///         account.
    /// @param account The address of the account for which the configuration was set.
    /// @param permissionId The permission ID associated with the Smart Session.
    /// @param lockTag The lock tag derived from the allocator, scope, and reset period.
    event SmartSessionEmissaryConfigEnabled(
        address indexed account, PermissionId permissionId, bytes12 indexed lockTag
    );

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
                                 ENABLE
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

        // Get the lockTag currently enabled for this permissionId and account
        bytes12 existingLockTag = $enabledLockTag[permissionId][account];

        // Check a lockTag is already enabled for this permissionId.
        // - First enable (isInit=false): Only user signature required
        // - Subsequent enables (isInit=true): Both user AND allocator signatures required
        //
        // Note: When allocator == address(0) (no allocator / NO_LOCKTAG flow),
        // the allocator signature check is always skipped regardless of isInit.
        bool isInit = existingLockTag != NO_LOCKTAG;

        // Revert if trying to set a different lockTag for the same permissionId
        if (isInit && existingLockTag != lockTag) {
            revert InvalidPermissionId(permissionId);
        }

        // Verify the user and allocator signatures
        hash.verifySignatures({
            allocator: config.allocator,
            user: account,
            allocatorSignature: enableData.allocatorSig,
            userSignature: enableData.userSig,
            isInit: isInit
        });

        // Enable session policies
        _enablePolicies({
            account: account,
            permissionId: permissionId,
            lockTag: lockTag,
            session: enableData.session.sessionToEnable
        });
    }

    /// @notice Enables all policies associated with a session for an account
    /// @param account The address of the account for which policies are being enabled
    /// @param permissionId The permission ID associated with the session
    /// @param lockTag The lock tag derived from the allocator, scope, and reset period
    /// @param session The session data containing policies to be enabled
    function _enablePolicies(
        address account,
        PermissionId permissionId,
        bytes12 lockTag,
        Session memory session
    )
        internal
        nonReentrant
    {
        // Enable ERC7739 content
        $enabledERC7739.enable({
            contexts: session.erc7739Policies.allowedERC7739Content,
            permissionId: permissionId,
            account: account
        });

        // Enable ERC1271 policies
        $erc1271Policies.enable({
            policyType: PolicyType.ERC1271,
            permissionId: permissionId,
            configId: permissionId.toErc1271PolicyId().toConfigId(account),
            policyDatas: session.erc7739Policies.erc1271Policies,
            account: account
        });

        // Enable action policies
        $actionPolicies.enable({
            permissionId: permissionId, actionPolicyDatas: session.actions, account: account
        });

        // Enable claim policies only if lockTag is not NO_LOCKTAG
        if (lockTag != NO_LOCKTAG) {
            $claimPolicies[lockTag].enable({
                policyType: PolicyType.ERC1271,
                permissionId: permissionId,
                configId: permissionId.toErc1271PolicyId().toConfigId(account),
                policyDatas: session.claimPolicies,
                account: account
            });
        }

        // Enable session validator if not already set
        if (address($sessionValidators[permissionId][account].sessionValidator) == address(0)) {
            $sessionValidators.enable({
                permissionId: permissionId,
                sessionValidator: session.sessionValidator,
                sessionValidatorConfig: session.sessionValidatorInitData,
                account: account
            });
        }

        // Add permissionId to enabled sessions
        $enabledSessions.add({ account: account, value: PermissionId.unwrap(permissionId) });

        // Set the lockTag for this permissionId and account
        $enabledLockTag[permissionId][account] = lockTag;

        // Emit event
        emit SmartSessionEmissaryConfigEnabled(account, permissionId, lockTag);
    }

    /*//////////////////////////////////////////////////////////////
                        REENTRANCY GUARD OVERRIDE
    //////////////////////////////////////////////////////////////*/

    /// @notice Always use transient reentrancy guard
    function _useTransientReentrancyGuardOnlyOnMainnet()
        internal
        view
        virtual
        override
        returns (bool)
    {
        return false;
    }
}
