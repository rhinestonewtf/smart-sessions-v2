// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

// Interfaces
import { ISmartSession } from "@smartsessions/ISmartSession.sol";
import { IERC7579Account } from "erc7579/interfaces/IERC7579Account.sol";
import { IActionPolicy } from "@smartsessions/interfaces/IPolicy.sol";

// Libraries
import { Execution, ExecutionLib } from "@smartsessions/lib/ExecutionLib.sol";
import { PolicyLib } from "@smartsessions/lib/PolicyLib.sol";
import { EnumerableSet } from "@smartsessions/utils/EnumerableSet4337.sol";
import { ValidationDataLib } from "@smartsessions/lib/ValidationDataLib.sol";
import { IdLib } from "@smartsessions/lib/IdLib.sol";

// Types
import {
    PermissionId,
    ActionId,
    Policy,
    ValidationData,
    RETRY_WITH_FALLBACK,
    FALLBACK_TARGET_FLAG,
    FALLBACK_ACTIONID_SMARTSESSION_CALL,
    FALLBACK_ACTIONID
} from "@smartsessions/DataTypes.sol";

library PolicyLibV2 {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using ExecutionLib for *;
    using EnumerableSet for *;
    using ValidationDataLib for *;
    using IdLib for *;
    using PolicyLib for *;
    using PolicyLibV2 for *;

    /*//////////////////////////////////////////////////////////////
                                 CHECK
    //////////////////////////////////////////////////////////////*/

    /// @dev Adjusted checkSingle7579Exec from PolicyLib to work with address instead of msg.sender
    function checkSingle7579Exec(
        mapping(ActionId => Policy) storage $policies,
        PermissionId permissionId,
        address target,
        uint256 value,
        bytes calldata callData,
        uint256 minPolicies,
        address account
    )
        internal
        returns (ValidationData vd)
    {
        // Extract the function selector from the call data
        bytes4 targetSig;
        if (callData.length < 4) {
            targetSig = IdLib.VALUE_SELECTOR;
        } else {
            targetSig = bytes4(callData[0:4]);
        }

        // Prevent potential bypass of policy checks through nested self executions
        if (targetSig == IERC7579Account.execute.selector && target == account) {
            revert ISmartSession.InvalidSelfCall();
        }

        // Prevent fallback action from being used directly
        if (target == FALLBACK_TARGET_FLAG) revert ISmartSession.InvalidTarget();

        // malloc for actionId
        ActionId actionId;

        // should the target of this call be the smart session module itself, we will use the
        // designated sentinel
        // actionId for smartsession calls. The user has to explicitly set the smartsession call
        // policy to allow this.
        // @dev this is a special case, as a session key should normally not be utilized to
        // configure other sessions
        if (target == address(this)) {
            actionId = FALLBACK_ACTIONID_SMARTSESSION_CALL;
        }
        // proceed with the normal flow
        else {
            // Generate the action ID based on the target and function selector
            actionId = target.toActionId(targetSig);
            // Check the relevant action policy
            vd = $policies[actionId].tryCheck({
                permissionId: permissionId,
                callOnIPolicy: abi.encodeCall(
                    IActionPolicy.checkAction,
                    (permissionId.toConfigId(actionId, account), account, target, value, callData)
                ),
                minPolicies: minPolicies,
                account: account
            });
            // If tryCheck returns RETRY_WITH_FALLBACK magic value, that means not enough policies
            // were configured
            // for the actionId. Proceed with checking fallback action policies
            // ($policies[FALLBACK_ACTIONID]).
            if (vd == RETRY_WITH_FALLBACK) actionId = FALLBACK_ACTIONID;
            // otherwise return the validation data
            else return vd;
        }
        // call the fallback policy for either FALLBACK_ACTIONID or
        // FALLBACK_ACTIONID_SMARTSESSION_CALL
        // If no policies were configured for FALLBACK_ACTIONID or
        // FALLBACK_ACTIONID_SMARTSESSION_CALL this call will
        // revert
        vd = $policies[actionId].check({
            permissionId: permissionId,
            callOnIPolicy: abi.encodeCall(
                IActionPolicy.checkAction,
                (permissionId.toConfigId(actionId, account), account, target, value, callData)
            ),
            minPolicies: minPolicies,
            account: account
        });
        return vd;
    }

    /// @dev Adjusted checkBatch7579Exec from PolicyLib to work with erc7579 Execution[] callData
    function checkBatch7579Exec(
        mapping(ActionId => Policy) storage $policies,
        Execution[] calldata executions,
        PermissionId permissionId,
        uint256 minPolicies,
        address account
    )
        internal
    {
        // Decode the batch of 7579 executions from the user operation's call data
        uint256 length = executions.length;
        // Revert if there are no executions in the batch
        if (length == 0) revert ISmartSession.NoExecutionsInBatch();

        // Iterate through each execution in the batch
        for (uint256 i; i < length; i++) {
            Execution calldata execution = executions[i];

            // Check policies for the current execution and intersect the result with previous
            // checks
            PolicyLibV2.checkSingle7579Exec({
                $policies: $policies,
                permissionId: permissionId,
                target: execution.target,
                value: execution.value,
                callData: execution.callData,
                minPolicies: minPolicies,
                account: account
            });
        }
    }

    /// @dev Adjusted check from PolicyLib to work with account address instead of msg.sender
    function check(
        Policy storage $self,
        PermissionId permissionId,
        bytes memory callOnIPolicy,
        uint256 minPolicies,
        address account
    )
        internal
        returns (ValidationData vd)
    {
        // Get the list of policies for the given permissionId and account
        address[] memory policies = $self.policyList[permissionId].values({ account: account });
        uint256 length = policies.length;

        // Ensure the minimum number of policies is met.
        // Revert otherwise. Current minPolicies for userOp policies is 0.
        // Current minPolicies for action policies is 1.
        // This ensures sudo (open) permissions can be created only by explicitly setting
        // SudoPolicy/YesPolicy
        // as the only action policies
        if (minPolicies > length) revert ISmartSession.NoPoliciesSet(permissionId);

        // Iterate over all policies and intersect the validation data
        for (uint256 i; i < length; i++) {
            // Intersect the validation data from this policy with the accumulated result
            vd = vd.intersect(policies[i].callPolicy(permissionId, callOnIPolicy));
        }
    }

    /// @dev Adjusted tryCheck from PolicyLib to work with account address instead of msg.sender
    function tryCheck(
        Policy storage $self,
        PermissionId permissionId,
        bytes memory callOnIPolicy,
        uint256 minPolicies,
        address account
    )
        internal
        returns (ValidationData vd)
    {
        // Get the list of policies for the given permissionId and account
        address[] memory policies = $self.policyList[permissionId].values({ account: account });
        uint256 length = policies.length;

        // Ensure the minimum number of policies is met. I.e. there are enough policies configured
        // for given ActionId
        // Current minPolicies is 1 for action policies. That means, if there is no policies at all
        // configured
        // for a given ActionId (ActionId was not enabled), execution proceeds to the fallback flow.
        // There can be any amount of fallback action policies configured, and those will be applied
        // to all actionIds,
        // that were not configured explicitly.
        if (minPolicies > length) {
            return RETRY_WITH_FALLBACK;
        }

        // Iterate over all policies and intersect the validation data
        for (uint256 i; i < length; i++) {
            // Intersect the validation data from this policy with the accumulated result
            vd = vd.intersect(policies[i].callPolicy(permissionId, callOnIPolicy));
        }

        // Make sure policies can't alter the control flow
        if (vd == RETRY_WITH_FALLBACK) revert ISmartSession.ForbiddenValidationData();
    }
}
