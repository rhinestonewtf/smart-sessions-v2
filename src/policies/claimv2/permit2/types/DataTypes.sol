// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Types
import { ParamCondition } from "@smartsessions/external/policies/ArgPolicy/ArgPolicy.sol";
import { ParamRules } from "@policies/claimv2/compact/types/DataTypes.sol";

/*//////////////////////////////////////////////////////////////
                            CONSTANTS
//////////////////////////////////////////////////////////////*/

// Field mode encoding (2 bits per field)
uint8 constant MODE_SKIP = 0; // 00 - Don't check this field
uint8 constant MODE_CHECK_STORAGE = 1; // 01 - Use storage (no catchall)
uint8 constant MODE_CHECK_CATCHALL = 2; // 10 - Use storage with catchall fallback
uint8 constant MODE_CHECK_SUBPOLICY = 3; // 11 - Delegate to external policy contract

// Field IDs for sub-policy delegation
uint8 constant FIELD_ARBITER = 0;
uint8 constant FIELD_DEADLINE = 1;
uint8 constant FIELD_TOKEN_IN = 2;
uint8 constant FIELD_RECIPIENT = 3;
uint8 constant FIELD_FILL_EXPIRY = 4;
uint8 constant FIELD_TOKEN_OUT = 5;
uint8 constant FIELD_ORIGIN_OPS = 6;
uint8 constant FIELD_DEST_OPS = 7;
uint8 constant FIELD_QUALIFICATION = 8;

/*//////////////////////////////////////////////////////////////
                            POLICY
//////////////////////////////////////////////////////////////*/

/// @notice Configuration for a sub-policy
/// @param fieldId The field this policy checks (0-8)
/// @param policyAddress The address of the policy contract
/// @param initData Initialization data for the policy
struct SubPolicyConfig {
    uint8 fieldId;
    address policyAddress;
    bytes initData;
}

/// @notice Storage config structures
/// @param chainId The chain ID for which this config applies (0 for catch-all)
/// @param token The token address
struct TokenInStorageConfig {
    uint256 chainId;
    address token;
}

/// @notice Storage config for recipient per target chain
/// @param targetChainId The target chain ID
/// @param recipient The recipient address
struct RecipientStorageConfig {
    uint256 targetChainId;
    address recipient;
}

/// @notice Storage config for fill expiry per target chain
/// @param targetChainId The target chain ID
/// @param minFillExpiry Minimum fill expiry (timestamp)
/// @param maxFillExpiry Maximum fill expiry (timestamp)
struct FillExpiryStorageConfig {
    uint256 targetChainId;
    uint128 minFillExpiry;
    uint128 maxFillExpiry;
}

/// @notice Storage config for tokenOut per target chain
/// @param targetChainId The target chain ID
/// @param token The token address
struct TokenOutStorageConfig {
    uint256 targetChainId;
    address token;
}

/// @notice Storage config for origin ops per chain
/// @param chainId The chain ID
/// @param requireOriginOps Whether origin ops are required
struct OriginOpsStorageConfig {
    uint256 chainId;
    bool requireOriginOps;
}

/// @notice Storage config for dest ops per target chain
/// @param targetChainId The target chain ID
/// @param requireDestOps Whether dest ops are required
struct DestOpsStorageConfig {
    uint256 targetChainId;
    bool requireDestOps;
}

/// @notice Storage config for qualification params
/// @param chainId The chain ID
/// @param arbiter The arbiter address
/// @param rules The parameter rules for qualification
struct QualificationStorageConfig {
    uint256 chainId;
    address arbiter;
    ParamRules rules;
}
