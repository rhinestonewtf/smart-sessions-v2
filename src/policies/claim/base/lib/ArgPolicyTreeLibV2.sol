// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Libraries
import {
    ArgPolicyTreeLib
} from "@smartsessions/external/policies/ArgPolicy/lib/ArgPolicyTreeLib.sol";

// Types
import { ParamRules, ParamRule } from "@policies/claim/base/types/BaseDataTypes.sol";
import { ParamCondition } from "@smartsessions/external/policies/ArgPolicy/ArgPolicy.sol";

/// @title ArgPolicyTree Library V2
/// @notice Adjusted ArgPolicyTreeLib to work with the new ParamRules struct that doesn't have value
///         and usage limits (compared to the original ArgPolicyTreeLib).
library ArgPolicyTreeLibV2 {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using ArgPolicyTreeLibV2 for *;
    using ArgPolicyTreeLib for *;

    /*//////////////////////////////////////////////////////////////
                                VALIDATE
    //////////////////////////////////////////////////////////////*/

    /// @dev Adjusted check to work with the new ParamRule struct and raw bytes data
    // solhint-disable-next-line code-complexity
    function check(ParamRule storage rule, bytes calldata data) internal view returns (bool) {
        // Cache the offset
        uint64 offset = rule.offset;
        // Cache the length
        uint8 length = rule.length;
        // Cache the condition
        ParamCondition condition = rule.condition;
        // Cache the reference value
        bytes32 ref = rule.ref;

        // Extract the specified number of bytes
        bytes32 param;

        // ------ This will revert if offset + length > data.length ------ //
        if (length > 0) {
            // For non zero length, extract only the specified number of bytes
            param = bytes32(data[offset:offset + length]);
        } else {
            // Otherwise, extract the full 32 bytes
            param = bytes32(data[offset:offset + 32]);
        }
        // -----------------------------------------------------------------//

        // CHECK Param Condition
        if (condition == ParamCondition.EQUAL && param != ref) {
            // Fails if parameter is not equal to reference value
            return false;
        } else if (condition == ParamCondition.GREATER_THAN && param <= ref) {
            // Fails if parameter is not greater than reference value
            return false;
        } else if (condition == ParamCondition.LESS_THAN && param >= ref) {
            // Fails if parameter is not less than reference value
            return false;
        } else if (condition == ParamCondition.GREATER_THAN_OR_EQUAL && param < ref) {
            // Fails if parameter is not greater than or equal to reference value
            return false;
        } else if (condition == ParamCondition.LESS_THAN_OR_EQUAL && param > ref) {
            // Fails if parameter is not less than or equal to reference value
            return false;
        } else if (condition == ParamCondition.NOT_EQUAL && param == ref) {
            // Fails if parameter equals reference value (should be different)
            return false;
        } else if (condition == ParamCondition.IN_RANGE) {
            // For IN_RANGE condition, rule.ref contains both min and max values
            // rule.ref format: first 128 bits = min value, last 128 bits = max value
            if (
                param < (ref >> 128) // Check if param is less than min value (high 128 bits)
                    || param
                        > (ref & 0x00000000000000000000000000000000ffffffffffffffffffffffffffffffff) // Check
                // if
                // param is greater than max value (low 128 bits)
            ) {
                return false;
            }
        }

        return true;
    }

    /// @dev Adjusted validateExpressionTree to work with the new ParamRules struct
    function validateExpressionTree(ParamRules memory rules) internal pure {
        // Cache length
        uint256 nodeCount = rules.packedNodes.length;
        uint256 ruleCount = rules.rules.length;

        // Check if the expression tree is empty
        require(nodeCount != 0, ArgPolicyTreeLib.EmptyExpressionTree());
        // Check if the root node index is within bounds
        require(rules.rootNodeIndex < nodeCount, ArgPolicyTreeLib.RootNodeIndexOutOfBounds());
        // Check if the number of rules exceeds the maximum allowed
        require(ruleCount <= ArgPolicyTreeLib.MAX_RULES, ArgPolicyTreeLib.TooManyRules());
        // Check if the number of nodes exceeds the maximum allowed
        require(nodeCount <= ArgPolicyTreeLib.MAX_NODES, ArgPolicyTreeLib.TooManyNodes());

        // Check each node in the tree
        for (uint8 i = 0; i < nodeCount; i++) {
            uint256 node = rules.packedNodes[i];
            uint8 nodeType = node.getNodeType();

            if (nodeType == ArgPolicyTreeLib.NODE_TYPE_RULE) {
                // Rule nodes must reference a valid rule
                uint8 ruleIndex = node.getRuleIndex();
                // Check if the rule index is within bounds
                require(ruleIndex < ruleCount, ArgPolicyTreeLib.RuleIndexOutOfBounds());
            } else if (nodeType == ArgPolicyTreeLib.NODE_TYPE_NOT) {
                // NOT nodes must have a valid child
                uint8 childIndex = node.getLeftChildIndex();
                // Check if the child index is within bounds
                require(childIndex < nodeCount, ArgPolicyTreeLib.NodeChildIndexOutOfBounds());
            } else {
                // AND or OR nodes
                // Must have valid left and right children
                uint8 leftChildIndex = node.getLeftChildIndex();
                uint8 rightChildIndex = node.getRightChildIndex();
                // Check if the left and right child indices are within bounds
                require(
                    leftChildIndex < nodeCount && rightChildIndex < nodeCount,
                    ArgPolicyTreeLib.NodeChildIndexOutOfBounds()
                );
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                                EVALUATE
    //////////////////////////////////////////////////////////////*/

    /// @dev Adjusted evaluateExpressionTree to work with the new ParamRules struct
    function evaluateExpressionTree(
        ParamRules storage rules,
        bytes calldata data
    )
        internal
        view
        returns (bool)
    {
        return evaluateNode(rules.packedNodes, rules.rootNodeIndex, rules.rules, data);
    }

    /// @dev Adjusted evaluateNode to work with the new ParamRule struct
    function evaluateNode(
        uint256[] storage packedNodes,
        uint8 nodeIndex,
        ParamRule[] storage rules,
        bytes calldata data
    )
        internal
        view
        returns (bool)
    {
        // Load the packed node from storage (single SLOAD operation)
        uint256 node = packedNodes[nodeIndex];

        // Extract node type
        uint8 nodeType = node.getNodeType();

        // Evaluate based on node type
        if (nodeType == ArgPolicyTreeLib.NODE_TYPE_RULE) {
            // Extract rule index
            uint8 ruleIndex = node.getRuleIndex();
            return rules[ruleIndex].check(data);
        } else if (nodeType == ArgPolicyTreeLib.NODE_TYPE_NOT) {
            // Extract child index
            uint8 childIndex = node.getLeftChildIndex();
            return !evaluateNode(packedNodes, childIndex, rules, data);
        } else if (nodeType == ArgPolicyTreeLib.NODE_TYPE_AND) {
            // Extract left child index
            uint8 leftChildIndex = node.getLeftChildIndex();
            // Evaluate left child first
            bool leftResult = evaluateNode(packedNodes, leftChildIndex, rules, data);
            // Short-circuit: if left result is false, the AND result is false
            if (!leftResult) return false;
            // Extract right child index
            uint8 rightChildIndex = node.getRightChildIndex();
            // Evaluate right child and return result
            return evaluateNode(packedNodes, rightChildIndex, rules, data);
        } else if (nodeType == ArgPolicyTreeLib.NODE_TYPE_OR) {
            // Extract left child index
            uint8 leftChildIndex = node.getLeftChildIndex();
            // Evaluate left child first
            bool leftResult = evaluateNode(packedNodes, leftChildIndex, rules, data);
            // Short-circuit: if left result is true, the OR result is true
            if (leftResult) return true;
            // Extract right child index
            uint8 rightChildIndex = node.getRightChildIndex();
            // Evaluate right child and return result
            return evaluateNode(packedNodes, rightChildIndex, rules, data);
        }

        // Should never reach here if the tree is valid
        return false;
    }

    /*//////////////////////////////////////////////////////////////
                                  FILL
    //////////////////////////////////////////////////////////////*/

    /// @dev Adjusted fill function to work with the new ParamRules struct
    function fill(ParamRules storage $config, ParamRules memory config) internal {
        // Set root node index
        $config.rootNodeIndex = config.rootNodeIndex;

        // Clear existing rules and packed nodes
        delete $config.rules;
        delete $config.packedNodes;

        // Add new rules
        for (uint256 i = 0; i < config.rules.length; i++) {
            $config.rules.push(config.rules[i]);
        }
        // Add new packed nodes
        for (uint256 i = 0; i < config.packedNodes.length; i++) {
            $config.packedNodes.push(config.packedNodes[i]);
        }
    }
}
