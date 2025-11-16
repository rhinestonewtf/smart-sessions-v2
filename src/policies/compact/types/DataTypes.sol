// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Types
import { ParamCondition } from "@smartsessions/external/policies/ArgPolicy/ArgPolicy.sol";

/*//////////////////////////////////////////////////////////////
                            POLICY
//////////////////////////////////////////////////////////////*/

/// @notice Stores the rules and their logical relationships
/// @param rootNodeIndex Index of the root node in the expression tree
/// @param rules Actual parameter rules
/// @param packedNodes Bit-packed nodes of the expression tree
struct ParamRules {
    uint8 rootNodeIndex;
    ParamRule[] rules;
    uint256[] packedNodes;
}

/// @notice Defines a condition to check against a parameter in calldata
/// @param condition Type of condition to check
/// @param offset Offset in calldata to read parameter (bytes)
/// @param length Length of the parameter in bytes (default is 32 bytes)
/// @param ref Reference value to compare against
struct ParamRule {
    ParamCondition condition;
    uint64 offset;
    uint8 length;
    bytes32 ref;
}

/// @notice Configuration for a single tokenIn entry (stored in enumerable set)
/// @dev Packed into bytes32: address (20 bytes) + bytes12 lockTag (12 bytes) = 32 bytes
struct TokenInConfig {
    address token; // address(0) for any token
    bytes12 lockTag; // bytes12(0) for any lockTag
}

/// @notice Configuration for recipient checking per targetChainId (targetChainId = 0 for catch-all)
struct RecipientConfig {
    address recipient;
}

/// @notice Configuration for fillExpiry checking per targetChainId (targetChainId = 0 for
/// catch-all)
struct FillExpiryConfig {
    uint256 packedFillExpiry; // uint128 min | uint128 max
}

/// @notice Configuration for a single tokenOut entry (stored in enumerable set)
/// @dev Just the token address
struct TokenOutConfig {
    address token; // address(0) for any token
}

/// @notice Configuration for ops requirements per chainId (chainId = 0 for catch-all)
struct OpsRequirementConfig {
    bool requireOriginOps; // true = must have non-empty originOps
    bool requireDestOps; // true = must have non-empty destOps
}

/// @notice Configuration for qualification checking per chainId (chainId = 0 for catch-all)
struct QualificationConfig {
    uint256 chainId; // Use 0 for catch-all
    bytes32 qualificationTypehash;
    ParamRules rules;
}
