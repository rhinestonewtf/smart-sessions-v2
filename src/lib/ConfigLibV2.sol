// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

// Interfaces
import { ISessionValidator } from "@smartsessions/interfaces/ISessionValidator.sol";
import { ISmartSession } from "@smartsessions/ISmartSession.sol";
import { IPolicy } from "@smartsessions/interfaces/IPolicy.sol";

// Libraries
import { FlatBytesLib } from "@flatbytes/BytesLib.sol";
import { IdLib } from "@smartsessions/lib/IdLib.sol";
import { EnumerableSet } from "@smartsessions/utils/EnumerableSet4337.sol";
import { ConfigLib } from "@smartsessions/lib/ConfigLib.sol";
import { HashLib } from "@smartsessions/lib/HashLib.sol";

// Types
import {
    PermissionId,
    SignerConf,
    ERC7579_MODULE_TYPE_STATELESS_VALIDATOR,
    EnumerableActionPolicy,
    ActionData,
    EMPTY_PERMISSIONID,
    ActionId,
    EMPTY_ACTIONID,
    PolicyType,
    Policy,
    ConfigId,
    PolicyData,
    EnumerableERC7739Config,
    ERC7739Context
} from "@smartsessions/DataTypes.sol";

/// @dev Extended ConfigLib library from SmartSessions to allow passing an address instead of
///      msg.sender for different enable functions.
library ConfigLibV2 {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using FlatBytesLib for FlatBytesLib.Bytes;
    using IdLib for *;
    using EnumerableSet for *;
    using ConfigLib for *;
    using ConfigLibV2 for *;
    using HashLib for *;

    /*//////////////////////////////////////////////////////////////
                                 ENABLE
    //////////////////////////////////////////////////////////////*/

    /// @dev Adjusted enable from ConfigLib to work with address instead of msg.sender
    function enable(
        mapping(
            PermissionId permissionId => mapping(address smartAccount => SignerConf conf)
        ) storage $sessionValidators,
        PermissionId permissionId,
        ISessionValidator sessionValidator,
        bytes memory sessionValidatorConfig,
        address account
    )
        internal
    {
        // Check if the sessionValidator is valid and supports the required interface
        if (
            address(sessionValidator) == address(0)
                || !sessionValidator.isModuleType(ERC7579_MODULE_TYPE_STATELESS_VALIDATOR)
        ) {
            revert ISmartSession.InvalidISessionValidator(sessionValidator);
        }

        // Get the storage reference for the signer configuration
        SignerConf storage $conf = $sessionValidators[permissionId][account];
        // Set the session validator
        $conf.sessionValidator = sessionValidator;

        // Store the signer configuration
        $conf.config.store(sessionValidatorConfig);
        emit ISmartSession.SessionValidatorEnabled(permissionId, address(sessionValidator), account);
    }

    /// @dev Adjusted enable from ConfigLib to work with address instead of msg.sender
    function enable(
        EnumerableActionPolicy storage $self,
        PermissionId permissionId,
        ActionData[] memory actionPolicyDatas,
        address account
    )
        internal
    {
        if (permissionId == EMPTY_PERMISSIONID) {
            revert ISmartSession.InvalidPermissionId(permissionId);
        }
        uint256 length = actionPolicyDatas.length;
        for (uint256 i; i < length; i++) {
            // record every enabled actionId
            ActionData memory actionPolicyData = actionPolicyDatas[i];

            ActionId actionId =
                actionPolicyData.actionTarget.toActionId(actionPolicyData.actionTargetSelector);
            {
                address _cacheTarget = actionPolicyData.actionTarget;
                // disallow actions to be set for address(0) or to the smartsession module itself
                // sessionkeys that have access to smartsessions, may use this access to elevate
                // their privileges
                // forgefmt: disable-next-item
                if (_cacheTarget == address(0) 
                 || _cacheTarget == address(this) 
                 || actionId == EMPTY_ACTIONID
                ) revert ISmartSession.InvalidActionId();
            }

            // Record the enabled action ID
            $self.actionPolicies[actionId].enable({
                policyType: PolicyType.ACTION,
                permissionId: permissionId,
                configId: permissionId.toConfigId(actionId, account),
                policyDatas: actionPolicyData.actionPolicies,
                account: account
            });

            // Record the enabled action ID
            $self.enabledActionIds[permissionId].add(account, ActionId.unwrap(actionId));
        }
    }

    /// @dev Adjusted enable from ConfigLib to work with address instead of msg.sender
    function enable(
        Policy storage $policy,
        PolicyType policyType,
        PermissionId permissionId,
        ConfigId configId,
        PolicyData[] memory policyDatas,
        address account
    )
        internal
    {
        // iterate over all policyData
        uint256 lengthConfigs = policyDatas.length;
        for (uint256 i; i < lengthConfigs; i++) {
            address policy = policyDatas[i].policy;

            policy.requirePolicyType(policyType);

            // Add the policy to the list for the given permission and smart account
            $policy.policyList[permissionId].add({ account: account, value: policy });

            // Initialize the policy with the provided configuration
            // overwrites the config
            IPolicy(policy)
                .initializeWithMultiplexer({
                    account: account, configId: configId, initData: policyDatas[i].initData
                });

            emit ISmartSession.PolicyEnabled(permissionId, policyType, policy, account);
        }
    }

    /// @dev Adjusted enable from ConfigLib to work with address instead of msg.sender
    function enable(
        EnumerableERC7739Config storage $enabledERC7739,
        ERC7739Context[] memory contexts,
        PermissionId permissionId,
        address account
    )
        internal
    {
        uint256 length = contexts.length;
        for (uint256 i; i < length; i++) {
            bytes32 appDomainSeparator = contexts[i].appDomainSeparator;

            uint256 contentNamesLength = contexts[i].contentNames.length;
            if (contentNamesLength != 0) {
                $enabledERC7739.enabledDomainSeparators[permissionId].add(
                    account, appDomainSeparator
                );
            }
            for (uint256 y; y < contentNamesLength; y++) {
                bytes32 contentHash = contexts[i].contentNames[y].hashERC7739Content();
                $enabledERC7739.enabledContentNames[permissionId][appDomainSeparator].add(
                    account, contentHash
                );
            }
        }
    }
}
