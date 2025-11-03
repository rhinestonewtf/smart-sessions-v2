// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.28;

// Contracts
import { NonceManager } from "@core/NonceManager.sol";

// Libraries
import { EnumerableSet } from "@smartsessions/utils/EnumerableSet4337.sol";
import { ConfigLib } from "@smartsessions/lib/ConfigLib.sol";
import { IdLib } from "@smartsessions/lib/IdLib.sol";
import { IdLibV2 } from "@lib/IdLibV2.sol";
import { HashLibV2 } from "@lib/HashLibV2.sol";
import { PolicyLib } from "@smartsessions/lib/PolicyLib.sol";
import { FlatBytesLib } from "@flatbytes/BytesLib.sol";
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

abstract contract SmartSessionManager is NonceManager, ISmartSessionEmissary {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using EnumerableSet for *;
    using ConfigLib for *;
    using ConfigLibV2 for *;
    using IdLib for *;
    using IdLibV2 for *;
    using HashLibV2 for *;
    using PolicyLib for *;
    using PolicyLibV2 for *;
    using FlatBytesLib for *;
    using SignatureLib for *;

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    // -- Permission Storage -- //

    /// @notice Set of enabled permission IDs per smart account
    EnumerableSet.Bytes32Set internal $enabledSessions;

    // -- Locktag Config Storage -- //

    /// @notice Maps enabled lockTags per account
    EnumerableSet.Bytes32Set internal $enabledLockTags;

    // -- Policy Storage -- //

    /// @notice Mapping of erc1271 policies organized by permission IDs and smart account
    Policy internal $erc1271Policies;
    /// @notice Set of all enabled ERC7739 configurations for each smart account and permissionId
    EnumerableERC7739Config internal $enabledERC7739;
    /// @notice Mapping of lockTag to claim policies
    mapping(bytes12 lockTag => Policy claimPolicies) internal $claimPolicies;
    /// @notice Mapping of lockTag to enabled action policies
    mapping(bytes12 lockTag => EnumerableActionPolicy) internal $actionPolicies;

    // -- Validator Config Storage -- //

    /// @notice Mapping of session validators organized by permission IDs and smart account
    ///         addresses
    mapping(PermissionId permissionId => mapping(address smartAccount => SignerConf conf)) internal
        $sessionValidators;

    /*//////////////////////////////////////////////////////////////
                           SESSION MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Enables a sessions for an account, using the provided enable data after verifying
    ///         required signatures.
    /// @param account The address of the account for which policies are being enabled
    /// @param enableData The data containing session and policy information to be enabled
    /// @param config The Smart Session Emissary configuration
    /// @param lockTag The lock tag associated with the session
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
        bytes32 hash =
            enableData.session.getAndVerifyDigest(account, nonce, enableData.expires, lockTag);

        // Check if the permissionId is already enabled for the account
        bool isInit = $enabledLockTags.contains({ account: account, value: bytes32(lockTag) });

        // Verify the user and allocator signatures
        hash.verifySignatures(
            config.allocator, account, enableData.allocatorSig, enableData.userSig, !isInit
        );

        // Enable ERC7739 content
        $enabledERC7739.enable(
            enableData.session.sessionToEnable.erc7739Policies.allowedERC7739Content,
            config.permissionId // TODO: Can we do this? Or do we need to do
                // session.toPermissionId()?
        );

        // Enable ERC1271 policies
        $erc1271Policies.enable({
            policyType: PolicyType.ERC1271,
            permissionId: config.permissionId,
            configId: config.permissionId.toErc1271PolicyId().toConfigId(),
            policyDatas: enableData.session.sessionToEnable.erc7739Policies.erc1271Policies,
            account: account
        });

        // Enable action and claim policies only if lockTag is not NO_LOCKTAG
        if (lockTag != NO_LOCKTAG) {
            // Enable action policies
            $actionPolicies[lockTag]
            .enable({
                permissionId: config.permissionId,
                actionPolicyDatas: enableData.session.sessionToEnable.actions,
                account: account
            });

            // Enable claim policies
            $claimPolicies[lockTag]
            .enable({
                policyType: PolicyType.ERC1271,
                permissionId: config.permissionId,
                configId: config.permissionId.toErc1271PolicyId().toConfigId(),
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
        if (!_isISessionValidatorSet(config.permissionId, account)) {
            $sessionValidators.enable({
                permissionId: config.permissionId,
                sessionValidator: enableData.session.sessionToEnable.sessionValidator,
                sessionValidatorConfig: enableData.session.sessionToEnable.sessionValidatorInitData,
                account: account
            });
        }

        // Add to enabled sessions
        $enabledSessions.add({ account: account, value: PermissionId.unwrap(config.permissionId) });
    }

    /// TODO: CHECK IF THIS FUNCTION IS NEEDED ANYMORE
    /// @notice Enable multiple sessions with their associated policies
    /// @param sessions An array of Session structures to be enabled
    /// @param account The account address associated with the sessions
    /// @return permissionIds An array of PermissionId values corresponding to the enabled sessions
    function _enableSessions(
        Session[] calldata sessions,
        address account,
        bytes12 lockTag
    )
        internal
        returns (PermissionId[] memory permissionIds)
    {
        uint256 length = sessions.length;
        if (length == 0) revert InvalidData();

        permissionIds = new PermissionId[](length);

        for (uint256 i; i < length; i++) {
            Session calldata session = sessions[i];
            PermissionId permissionId = session.toPermissionId();

            // Enable ERC7739 content
            $enabledERC7739.enable(
                session.erc7739Policies.allowedERC7739Content,
                permissionId // TODO: Can we do this? Or do we need to do
                    // session.toPermissionId()?
            );

            // Enable ERC1271 policies
            $erc1271Policies.enable({
                policyType: PolicyType.ERC1271,
                permissionId: permissionId,
                configId: permissionId.toErc1271PolicyId().toConfigId(account),
                policyDatas: session.erc7739Policies.erc1271Policies,
                account: account
            });

            // Only enable claim and action policies if lockTag is not NO_LOCKTAG
            if (lockTag != NO_LOCKTAG) {
                // Enable claim policies
                $claimPolicies[lockTag]
                .enable({
                    policyType: PolicyType.ERC1271,
                    permissionId: permissionId,
                    configId: permissionId.toErc1271PolicyId().toConfigId(account),
                    policyDatas: session.claimPolicies,
                    account: account
                });

                // Enable action policies
                $actionPolicies[lockTag]
                .enable({
                    permissionId: permissionId, actionPolicyDatas: session.actions, account: account
                });

                // Add the lockTag to the enabled lockTags for the account
                $enabledLockTags.add({ account: account, value: bytes32(lockTag) });
            }

            // Enable the ISessionValidator for this session
            if (!_isISessionValidatorSet(permissionId, account)) {
                $sessionValidators.enable({
                    permissionId: permissionId,
                    sessionValidator: session.sessionValidator,
                    sessionValidatorConfig: session.sessionValidatorInitData,
                    account: account
                });
            }
            permissionIds[i] = permissionId;
            emit SessionCreated(permissionId, account);

            // Add to enabled sessions
            $enabledSessions.add({ account: account, value: PermissionId.unwrap(permissionId) });
        }
    }

    /// @notice Disables sessions for an account, using the provided disable data after verifying
    ///         required signatures.
    /// @param account The address of the account for which policies are being disabled
    /// @param disableData The data containing session and policy information to be disabled
    /// @param permissionId The unique identifier for the permission set
    /// @param lockTag The lock tag associated with the session
    /// @param allocator The address of the allocator for the session
    /// @param allocatorSig The signature from the allocator authorizing the session
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
        bytes32 hash =
            disableData.getAndVerifyDigest(permissionId, account, nonce, expires, lockTag);

        // Verify the user and allocator signatures
        hash.verifySignatures(allocator, account, allocatorSig, userSig, false);

        // Remove the session from the smart session config
        _removeSession(permissionId, account, lockTag);
    }

    /// @notice Remove a session and all its associated policies
    /// @param permissionId The unique identifier for the session to be removed
    /// @param account The account address associated with the session
    /// @param lockTag The lock tag used to identify the session
    function _removeSession(
        PermissionId permissionId,
        address account,
        bytes12 lockTag
    )
        internal
    {
        if (permissionId == EMPTY_PERMISSIONID) revert InvalidSession(permissionId);

        // Remove all ERC1271 policies for this session
        $erc1271Policies.policyList[permissionId].removeAll(account);

        // Remove all Action policies for this session
        uint256 actionLength =
            $actionPolicies[lockTag].enabledActionIds[permissionId].length(account);
        for (uint256 i; i < actionLength; i++) {
            ActionId actionId = ActionId.wrap(
                $actionPolicies[lockTag].enabledActionIds[permissionId].at(account, i)
            );
            $actionPolicies[lockTag].actionPolicies[actionId].policyList[permissionId]
            .removeAll(account);
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

        emit SessionRemoved(permissionId, account);
    }

    /*//////////////////////////////////////////////////////////////
                              SESSION HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get the session digest for verification
    /// @param account The account address
    /// @param lockTag The lock tag used to identify the session
    /// @param data The session data
    /// @param expires The expiration timestamp for the session
    /// @param sender The address of the sender for the session, if applicable
    /// @return The session digest
    function getSessionDigest(
        address account,
        Session memory data,
        bytes12 lockTag,
        uint256 expires,
        address sender
    )
        public
        view
        returns (bytes32)
    {
        uint256 nonce = $emissaryNonce[account][lockTag];
        return
            data.sessionDigest({
                account: account, lockTag: lockTag, expires: expires, nonce: nonce
            });
    }

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

    /// @notice Internal function to check if a session validator is set
    /// @param permissionId The permission ID to check
    /// @param account The account address
    /// @return Boolean indicating whether the session validator is set
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

    /*//////////////////////////////////////////////////////////////
                              STATUS CHECKS
    //////////////////////////////////////////////////////////////*/

    // TODO: Port from SmartSessionsV1? This might not be needed/fit

    /*//////////////////////////////////////////////////////////////
                              GETTERS
    //////////////////////////////////////////////////////////////*/

    // TODO: Port remaining getters from SmartSessionsV1

    /// @notice Get the action policies for a specific action ID
    /// @param account The account address
    /// @param permissionId The permission ID
    /// @param actionId The action ID
    /// @param lockTag The associated lock tag
    /// @return Array of policy addresses
    function getActionPolicies(
        address account,
        PermissionId permissionId,
        ActionId actionId,
        bytes12 lockTag
    )
        external
        view
        returns (address[] memory)
    {
        return
            $actionPolicies[lockTag].actionPolicies[actionId].policyList[permissionId]
            .values(account);
    }

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

    /// @notice Get all enabled actions for an account
    /// @param account The account address
    /// @param permissionId The permission ID
    /// @param lockTag The associated lock tag
    /// @return Array of enabled action IDs as bytes32
    function getEnabledActions(
        address account,
        PermissionId permissionId,
        bytes12 lockTag
    )
        external
        view
        returns (bytes32[] memory)
    {
        return $actionPolicies[lockTag].enabledActionIds[permissionId].values(account);
    }

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

    /*//////////////////////////////////////////////////////////////
                                  7579
    //////////////////////////////////////////////////////////////*/

    /// @notice Initialize the module with the given data
    /// @param data The data to initialize the module with, encoded as per the expected format:
    ///        abi.encodePacked(SmartSessionMode, abi.encode(Session[]))
    /// @dev If no data is provided, the module will be installed without any sessions
    function onInstall(bytes calldata data) external {
        /// TODO: Call setConfig
    }

    /// @notice Uninstall the module and clean up associated sessions for the msg.sender
    function onUninstall(
        bytes calldata /*data*/
    )
        external {
        /// TODO: This will require allocator sig
    }

    /// @notice Check if the module is initialized for a specific smart account
    /// @param smartAccount The smart account address to check
    /// @return Boolean indicating whether the module is initialized
    function isInitialized(address smartAccount) external view returns (bool) {
        // Check if there are any enabled lockTags for the smart account
        return $enabledLockTags.length({ account: smartAccount }) != 0;
    }

    /// @notice Check if the module type matches the validator type
    /// @param typeID The type ID to check
    /// @return Boolean indicating whether the module type matches
    function isModuleType(uint256 typeID) external pure returns (bool) {
        return typeID == ERC7579_MODULE_TYPE_VALIDATOR;
    }
}
