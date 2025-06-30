// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Types
import { ParamCondition } from "@smartsessions/external/policies/ArgPolicy/ArgPolicy.sol";

/*//////////////////////////////////////////////////////////////
                            POLICY
//////////////////////////////////////////////////////////////*/

/// @notice Token amount configuration for checking per chain
struct TokenAmountConfig {
    address token; // Token address (address(0) for any token)
    uint128 minAmount; // Minimum amount (0 for no minimum)
    uint128 maxAmount; // Maximum amount (type(uint128).max for no maximum)
}

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
/// @param isLimited Whether this parameter has a usage limit
/// @param ref Reference value to compare against
/// @param usage Limit information if isLimited is true
struct ParamRule {
    ParamCondition condition;
    uint64 offset;
    bool isLimited;
    bytes32 ref;
}

/// @notice Configuration for tokenIn checking per chainId
struct TokenInConfig {
    uint256 chainId;
    TokenAmountConfig config;
}

/// @notice Configuration for tokenOut checking per targetChainId
struct TokenOutConfig {
    uint256 targetChainId;
    TokenAmountConfig config;
}

/*//////////////////////////////////////////////////////////////
                        MULITCHAINCOMPACT
//////////////////////////////////////////////////////////////*/

struct Token {
    address token;
    uint256 amount;
}

struct Op {
    bytes data;
}

struct Qualification {
    bytes data;
}

struct Target {
    address recipient;
    Token[] tokenOut;
    uint256 targetChain;
    uint256 fillExpires;
}

struct Lock {
    bytes12 lockTag;
    address token;
    uint256 amount;
}

struct Mandate {
    Target target;
    Op[] preClaimOps;
    Op[] targetOps;
    Qualification q;
}

struct Element {
    address arbiter;
    uint256 chainId;
    Lock[] commitments;
    Mandate mandate;
}

struct MultichainCompact {
    address sponsor;
    uint256 nonce;
    uint256 expires;
    Element notarizedElement;
    bytes32[] otherElements;
}
