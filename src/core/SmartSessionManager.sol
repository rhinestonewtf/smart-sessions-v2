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

// Interfaces
import { ISmartSessionExecutionVerifier } from "@interfaces/ISmartSessionExecutionVerifier.sol";
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
    Policy
} from "@smartsessions/DataTypes.sol";

abstract contract SmartSessionManager is NonceManager, ISmartSessionExecutionVerifier, Ownable {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using EnumerableSet for *;
    using ConfigLib for *;
    using IdLib for *;
    using HashLib for *;
    using PolicyLib for *;
    using FlatBytesLib for *;

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Mapping of user address => set of enabled PermissionIds
    EnumerableSet.Bytes32Set internal $enabledSessions;
    /// @notice Mapping of whitelisted sources
    mapping(address source => bool isWhitelisted) public $whitelistedSources;
    /// @notice Mapping of action policies organized by action IDs and permission IDs
    EnumerableActionPolicy internal $actionPolicies;
    /// @notice Mapping of session validators organized by permission IDs and smart account
    /// addresses
    mapping(PermissionId permissionId => mapping(address smartAccount => SignerConf conf)) internal
        $sessionValidators;

    /*//////////////////////////////////////////////////////////////
                               MODIFIERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Only allow calls from whitelisted sources
    modifier onlyWhitelistedSource() {
        // Check if the sender is a whitelisted source
        if (!$whitelistedSources[msg.sender]) {
            revert UnauthorizedSource();
        }
        _;
    }

    /// @notice Before enabling policies, we need to check if the session is enabled for the caller
    /// and the
    /// given permission, after enabling policies, we need to check if the session is still enabled
    /// for the caller and
    /// the given permission. This is to ensure that the session is still enabled after the
    /// operation and no re-entrancy is possible
    /// @param permissionId The unique identifier for the permission
    modifier enableWithPermissionId(PermissionId permissionId) {
        // Check if the session is enabled for the caller and the given permission before enabling
        // policies on it
        $enabledSessions.requirePermissionIdEnabled(permissionId);
        _;
        // Check if the session is enabled for the caller and the given permission after enabling
        // policies on it
        // this is to ensure that the session is still enabled after the operation and no
        // re-entrancy is possible
        $enabledSessions.requirePermissionIdEnabled(permissionId);
    }

    /// @notice Before disabling policies, we need to check if the session is enabled for the caller
    ///         and the given permission
    /// @param permissionId The unique identifier for the permission
    modifier disableWithPermissionId(PermissionId permissionId) {
        // Check if the session is enabled for the caller and the given permission before enabling
        // policies on it
        $enabledSessions.requirePermissionIdEnabled(permissionId);
        _;
    }

    /*//////////////////////////////////////////////////////////////
                                 ADMIN
    //////////////////////////////////////////////////////////////*/

    /// @notice Set the whitelisted status for an address
    /// @param source The address to be whitelisted
    /// @param isWhitelisted The whitelisted status to be set
    function setWhitelistedSource(address source, bool isWhitelisted) external onlyOwner {
        // Set the whitelisted status for the address
        $whitelistedSources[source] = isWhitelisted;
        emit WhitelistStatusUpdated(source, isWhitelisted);
    }

    /*//////////////////////////////////////////////////////////////
                           ACTION POLICY MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Enable action policies for a specific permission
    /// @param permissionId The unique identifier for the permission
    /// @param actionPolicies An array of ActionData structures containing action policy information
    function enableActionPolicies(
        PermissionId permissionId,
        ActionData[] memory actionPolicies
    )
        public
        enableWithPermissionId(permissionId)
    {
        // Enable the action policies
        $actionPolicies.enable({
            permissionId: permissionId,
            actionPolicyDatas: actionPolicies,
            useRegistry: true
        });
    }

    /// @notice Disable specific action policies for a given permission and action ID
    /// @param permissionId The unique identifier for the permission
    /// @param actionId The specific action identifier
    function disableActionId(
        PermissionId permissionId,
        ActionId actionId
    )
        public
        disableWithPermissionId(permissionId)
    {
        // Disable all action policies for the given action ID
        // No need to emit events here, as unlike with 7739contents and 1271 policies,
        // here disabling the actionId means all action policies are also disabled
        $actionPolicies.actionPolicies[actionId].policyList[permissionId].removeAll(msg.sender);

        // remove action Id from enabledActionIds
        $actionPolicies.enabledActionIds[permissionId].remove(msg.sender, ActionId.unwrap(actionId));
        emit ISmartSession.ActionIdDisabled(permissionId, actionId, msg.sender);
    }

    /// @notice Disable action id for a given permission and action ID
    /// @param permissionId The unique identifier for the permission
    /// @param actionId The specific action identifier
    /// @param policies An array of policy addresses to be disabled
    function disableActionPolicies(
        PermissionId permissionId,
        ActionId actionId,
        address[] calldata policies
    )
        public
        disableWithPermissionId(permissionId)
    {
        // Disable the specified action policies for the given action ID
        $actionPolicies.actionPolicies[actionId].disable({
            policyType: PolicyType.ACTION,
            smartAccount: msg.sender,
            permissionId: permissionId,
            policies: policies
        });

        // remove the actionId from the enabledActionIds if no policies are left
        if (
            $actionPolicies.actionPolicies[actionId].policyList[permissionId].length(msg.sender)
                == 0
        ) {
            $actionPolicies.enabledActionIds[permissionId].remove(
                msg.sender, ActionId.unwrap(actionId)
            );
            emit ISmartSession.ActionIdDisabled(permissionId, actionId, msg.sender);
        }
    }

    /*//////////////////////////////////////////////////////////////
                           SESSION MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Enable multiple sessions with their associated policies
    /// @dev Since this function is only called during the ERC-4337 execution phase, it is safe to
    ///      use the registry
    /// @param sessions An array of Session structures to be enabled
    /// @return permissionIds An array of PermissionId values corresponding to the enabled sessions
    function enableSessions(Session[] calldata sessions)
        external
        returns (PermissionId[] memory permissionIds)
    {
        return _enableSessions(sessions, true);
    }

    /// @notice Enable multiple sessions with their associated policies
    /// @param sessions An array of Session structures to be enabled
    /// @param useRegistry A flag to indicate whether to use a registry check for the policies and
    ///        session validator
    /// @return permissionIds An array of PermissionId values corresponding to the enabled sessions
    function _enableSessions(
        Session[] calldata sessions,
        bool useRegistry
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

            // Enable Action policies
            $actionPolicies.enable({
                permissionId: permissionId,
                actionPolicyDatas: session.actions,
                useRegistry: useRegistry
            });

            // Add the session to the list of enabled sessions for the caller
            $enabledSessions.add({ account: msg.sender, value: PermissionId.unwrap(permissionId) });

            // Enable the ISessionValidator for this session
            if (!_isISessionValidatorSet(permissionId, msg.sender)) {
                $sessionValidators.enable({
                    permissionId: permissionId,
                    sessionValidator: session.sessionValidator,
                    sessionValidatorConfig: session.sessionValidatorInitData,
                    useRegistry: useRegistry
                });
            }
            permissionIds[i] = permissionId;
            emit SessionCreated(permissionId, msg.sender);
        }
    }

    /// @notice Remove a session and all its associated policies
    /// @param permissionId The unique identifier for the session to be removed
    function removeSession(PermissionId permissionId) public {
        if (permissionId == EMPTY_PERMISSIONID) revert InvalidSession(permissionId);

        // Remove all Action policies for this session
        uint256 actionLength = $actionPolicies.enabledActionIds[permissionId].length(msg.sender);
        for (uint256 i; i < actionLength; i++) {
            ActionId actionId =
                ActionId.wrap($actionPolicies.enabledActionIds[permissionId].at(msg.sender, i));
            $actionPolicies.actionPolicies[actionId].policyList[permissionId].removeAll(msg.sender);
        }

        // removing all stored actionIds
        $actionPolicies.enabledActionIds[permissionId].removeAll(msg.sender);

        $sessionValidators.disable({ permissionId: permissionId, smartAccount: msg.sender });

        // Remove all ERC1271 policies for this session
        $enabledSessions.remove({ account: msg.sender, value: PermissionId.unwrap(permissionId) });
        emit SessionRemoved(permissionId, msg.sender);
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
    /// @return Boolean indicating whether the permission is enabled
    function isPermissionEnabled(
        PermissionId permissionId,
        address account
    )
        external
        view
        returns (bool)
    {
        return $enabledSessions.contains(account, PermissionId.unwrap(permissionId));
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

    /// @notice Gets all permission IDs for a specific account
    /// @param account The address of the account to query
    /// @return permissionIds Array of permission IDs associated with the account
    function getPermissionIDs(address account)
        external
        view
        returns (PermissionId[] memory permissionIds)
    {
        bytes32[] memory _permissionIds = $enabledSessions.values(account);
        assembly {
            permissionIds := _permissionIds
        }
    }
}
