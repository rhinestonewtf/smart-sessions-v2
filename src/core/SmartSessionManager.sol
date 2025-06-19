// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.28;

// Contracts
import { NonceManager } from "@core/NonceManager.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

// Libraries
import { EnumerableSet } from "@smartsessions/utils/EnumerableSet4337.sol";
import { ConfigLib } from "@smartsessions/lib/ConfigLib.sol";
import { IdLib } from "@smartsessions/lib/IdLib.sol";
import { HashLib } from "@smartsessions/lib/HashLib.sol";
import { PolicyLib } from "@smartsessions/lib/PolicyLib.sol";
import { FlatBytesLib } from "@flatbytes/BytesLib.sol";
import { ConfigLibV2 } from "@lib/ConfigLibV2.sol";

// Interfaces
import { ISmartSessionEmissary } from "@interfaces/ISmartSessionEmissary.sol";
import { ISmartSession } from "@smartsessions/ISmartSession.sol";

// Types
import {
    PermissionId,
    ActionId,
    ActionData,
    Session,
    SmartSessionMode,
    SignerConf,
    EnumerableActionPolicy,
    PolicyType,
    EMPTY_PERMISSIONID,
    Policy,
    EnumerableERC7739Config,
    ERC7739ContextHashes
} from "@smartsessions/DataTypes.sol";

abstract contract SmartSessionManager is NonceManager, ISmartSessionEmissary {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using EnumerableSet for *;
    using ConfigLib for *;
    using ConfigLibV2 for *;
    using IdLib for *;
    using HashLib for *;
    using PolicyLib for *;
    using FlatBytesLib for *;

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Maps lockTag to enabled permissionIds for verifyClaim lookups
    /// @dev Bridge storage connecting emissary lockTags to SmartSession permissionIds
    mapping(address sender => mapping(bytes12 lockTag => EnumerableSet.Bytes32Set permissionIDs))
        internal $smartSessionConfig;
    /// @notice Mapping of whitelisted sources
    mapping(address source => bool isWhitelisted) public $whitelistedSources;
    /// @notice Mapping of action policies organized by action IDs and permission IDs
    EnumerableActionPolicy internal $actionPolicies;
    /// @notice Mapping of erc1271 policies organized by permission IDs and smart account
    Policy internal $erc1271Policies;
    /// @notice Mapping of enabled erc7739 configurations per user address
    EnumerableERC7739Config internal $enabledERC7739;
    /// @notice Mapping of session validators organized by permission IDs and smart account
    ///         addresses
    mapping(PermissionId permissionId => mapping(address smartAccount => SignerConf conf)) internal
        $sessionValidators;

    /*//////////////////////////////////////////////////////////////
                           SESSION MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Enable multiple sessions with their associated policies
    /// @param sessions An array of Session structures to be enabled
    /// @param account The account address associated with the sessions
    /// @param useRegistry A flag to indicate whether to use a registry check for the policies and
    ///        session validator
    /// @param lockTag A tag used to lock the session configuration
    /// @param arbiter The address of the arbiter for the session, if applicable
    /// @return permissionIds An array of PermissionId values corresponding to the enabled sessions
    function _enableSessions(
        Session[] calldata sessions,
        address account,
        bool useRegistry,
        bytes12 lockTag,
        address arbiter
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

            // Enable ERC1271 policies
            $erc1271Policies.enable({
                policyType: PolicyType.ERC1271,
                permissionId: permissionId,
                configId: permissionId.toErc1271PolicyId().toConfigId(),
                policyDatas: session.erc7739Policies.erc1271Policies,
                useRegistry: useRegistry,
                account: account
            });
            $enabledERC7739.enable(
                session.erc7739Policies.allowedERC7739Content, permissionId, account
            );

            // Enable Action policies
            $actionPolicies.enable({
                permissionId: permissionId,
                actionPolicyDatas: session.actions,
                useRegistry: useRegistry,
                account: account
            });

            // Add the session to the list of enabled sessions for the caller
            $smartSessionConfig[arbiter][lockTag].add({
                account: account,
                value: PermissionId.unwrap(permissionId)
            });

            // Enable the ISessionValidator for this session
            if (!_isISessionValidatorSet(permissionId, account)) {
                $sessionValidators.enable({
                    permissionId: permissionId,
                    sessionValidator: session.sessionValidator,
                    sessionValidatorConfig: session.sessionValidatorInitData,
                    useRegistry: useRegistry,
                    account: account
                });
            }
            permissionIds[i] = permissionId;
            emit SessionCreated(permissionId, account);
        }
    }

    /// @notice Remove a session and all its associated policies
    /// @param permissionId The unique identifier for the session to be removed
    /// @param account The account address associated with the session
    function _removeSession(
        PermissionId permissionId,
        address account,
        bytes12 lockTag,
        address arbiter
    )
        internal
    {
        if (permissionId == EMPTY_PERMISSIONID) revert InvalidSession(permissionId);

        // Remove all ERC1271 policies for this session
        $erc1271Policies.policyList[permissionId].removeAll(msg.sender);

        // Remove all Action policies for this session
        uint256 actionLength = $actionPolicies.enabledActionIds[permissionId].length(account);
        for (uint256 i; i < actionLength; i++) {
            ActionId actionId =
                ActionId.wrap($actionPolicies.enabledActionIds[permissionId].at(account, i));
            $actionPolicies.actionPolicies[actionId].policyList[permissionId].removeAll(account);
        }

        // removing all stored actionIds
        $actionPolicies.enabledActionIds[permissionId].removeAll(account);

        $sessionValidators.disable({ permissionId: permissionId, smartAccount: account });

        // Remove all ERC1271 policies for this session
        $smartSessionConfig[arbiter][lockTag].remove({
            account: account,
            value: PermissionId.unwrap(permissionId)
        });
        emit SessionRemoved(permissionId, account);
    }

    /*//////////////////////////////////////////////////////////////
                              SESSION HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get the session digest for verification
    /// @param permissionId The unique identifier for the permission
    /// @param account The account address
    /// @param data The session data
    /// @param mode The smart session mode
    /// @return The session digest
    function getSessionDigest(
        PermissionId permissionId,
        address account,
        Session memory data,
        SmartSessionMode mode
    )
        public
        view
        returns (bytes32)
    {
        // TODO: Check if we can use emissaryNonce for this
        uint256 nonce = $signerNonce[permissionId][account];
        return data.sessionDigest({ account: account, mode: mode, nonce: nonce });
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

    /// @notice Check if a session validator is set
    /// @param permissionId The permission ID to check
    /// @param account The account address
    /// @return Boolean indicating whether the session validator is set
    function isISessionValidatorSet(
        PermissionId permissionId,
        address account
    )
        external
        view
        returns (bool)
    {
        return _isISessionValidatorSet(permissionId, account);
    }

    /// @notice Check if a permission is enabled for an account
    /// @param permissionId The permission ID to check
    /// @param account The account address
    /// @param lockTag The lock tag used to identify the session
    /// @param arbiter The address of the arbiter for the session, if applicable
    /// @return Boolean indicating whether the permission is enabled
    function isPermissionEnabled(
        PermissionId permissionId,
        address account,
        bytes12 lockTag,
        address arbiter
    )
        external
        view
        returns (bool)
    {
        return $smartSessionConfig[arbiter][lockTag].contains(
            account, PermissionId.unwrap(permissionId)
        );
    }

    /// @notice Check if actions are enabled for an account
    /// @param account The account address
    /// @param permissionId The permission ID
    /// @param actions The action data array to check
    /// @return Boolean indicating whether the actions are enabled
    function areActionsEnabled(
        address account,
        PermissionId permissionId,
        ActionData[] calldata actions
    )
        external
        view
        returns (bool)
    {
        return $actionPolicies.areEnabled({
            permissionId: permissionId,
            smartAccount: account,
            actionPolicyDatas: actions
        });
    }

    /// @notice Check if an action policy is enabled
    /// @param account The account address
    /// @param permissionId The permission ID
    /// @param actionId The action ID
    /// @param policy The policy address
    /// @return Boolean indicating whether the action policy is enabled
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
        return $actionPolicies.actionPolicies[actionId].policyList[permissionId].contains(
            account, policy
        );
    }

    /// @notice Check if an action ID is enabled
    /// @param account The account address
    /// @param permissionId The permission ID
    /// @param actionId The action ID
    /// @return Boolean indicating whether the action ID is enabled
    function isActionIdEnabled(
        address account,
        PermissionId permissionId,
        ActionId actionId
    )
        external
        view
        returns (bool)
    {
        return $actionPolicies.enabledActionIds[permissionId].contains(
            account, ActionId.unwrap(actionId)
        );
    }

    /// @notice Check if an ERC1271 policy is enabled for a specific account and permission ID
    /// @param account The account address
    /// @param permissionId The permission ID
    /// @param policy The policy address
    /// @return Boolean indicating whether the ERC1271 policy is enabled
    function isERC1271PolicyEnabled(
        address account,
        PermissionId permissionId,
        address policy
    )
        external
        view
        returns (bool)
    {
        return $erc1271Policies.policyList[permissionId].contains(account, policy);
    }

    /// @notice Check if an ERC7739 content is enabled for a specific account and permission ID
    /// @param account The account address
    /// @param permissionId The permission ID
    /// @param appDomainSeparator The app domain separator for the ERC7739 content
    /// @param content The content string to check
    function isERC7739ContentEnabled(
        address account,
        PermissionId permissionId,
        bytes32 appDomainSeparator,
        string memory content
    )
        external
        view
        returns (bool)
    {
        return $enabledERC7739.enabledContentNames[permissionId][appDomainSeparator].contains(
            account, content.hashERC7739Content()
        );
    }

    /*//////////////////////////////////////////////////////////////
                              GETTERS
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

    /// @notice Get all enabled ERC7739 content for an account and permission ID
    /// @param account The account address
    /// @param permissionId The permission ID
    /// @return enabledERC7739ContentHashes An array of ERC7739ContextHashes
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
            enabledERC7739ContentHashes[i].appDomainSeparator =
                $enabledERC7739.enabledDomainSeparators[permissionId].at(account, i);
            enabledERC7739ContentHashes[i].contentNameHashes = $enabledERC7739.enabledContentNames[permissionId][enabledERC7739ContentHashes[i]
                .appDomainSeparator].values(account);
        }
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

    /// @notice Gets all permission IDs for a specific account and lock tag
    /// @param account The address of the account to query
    /// @param lockTag The lock tag used to identify the session configuration
    /// @param arbiter The address of the arbiter for the session, if applicable
    /// @return permissionIds Array of permission IDs associated with the account
    function getPermissionIDs(
        address account,
        bytes12 lockTag,
        address arbiter
    )
        external
        view
        returns (PermissionId[] memory permissionIds)
    {
        bytes32[] memory _permissionIds = $smartSessionConfig[arbiter][lockTag].values(account);
        assembly {
            permissionIds := _permissionIds
        }
    }
}
