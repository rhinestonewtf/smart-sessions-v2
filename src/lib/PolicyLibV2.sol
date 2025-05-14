// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.28;

// Interfaces
import { ISmartSession } from "@smartsessions/ISmartSession.sol";

// Libraries
import { Execution, ExecutionLib } from "@smartsessions/lib/ExecutionLib.sol";
import { PolicyLib } from "@smartsessions/lib/PolicyLib.sol";

// Types
import { PermissionId, ActionId, Policy } from "@smartsessions/DataTypes.sol";

library PolicyLibV2 {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using ExecutionLib for bytes;

    /*//////////////////////////////////////////////////////////////
                                 CHECK
    //////////////////////////////////////////////////////////////*/

    function checkBatch7579Exec(
        mapping(ActionId => Policy) storage $policies,
        bytes calldata callData,
        PermissionId permissionId,
        uint256 minPolicies
    )
        internal
    {
        // Decode the batch of 7579 executions from the user operation's call data
        Execution[] calldata executions = callData.decodeUserOpCallData().decodeBatch();
        uint256 length = executions.length;
        // Revert if there are no executions in the batch
        if (length == 0) revert ISmartSession.NoExecutionsInBatch();

        // Iterate through each execution in the batch
        for (uint256 i; i < length; i++) {
            Execution calldata execution = executions[i];

            // Check policies for the current execution and intersect the result with previous
            // checks
            PolicyLib.checkSingle7579Exec({
                $policies: $policies,
                permissionId: permissionId,
                target: execution.target,
                value: execution.value,
                callData: execution.callData,
                minPolicies: minPolicies
            });
        }
    }
}
