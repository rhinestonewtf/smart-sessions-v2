// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Types
import { ParamCondition } from "@smartsessions/external/policies/ArgPolicy/ArgPolicy.sol";

/*//////////////////////////////////////////////////////////////
                    ARCHITECTURE OVERVIEW
//////////////////////////////////////////////////////////////

This module defines shared types for the ClaimPolicy family.
Two policies share most logic:

┌─────────────────────────────────────────────────────────────┐
│                    BaseClaimPolicy (Abstract)               │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  Shared Fields (8/9):                                 │  │
│  │  • Arbiter          • Recipient      • OriginOps      │  │
│  │  • Expiry*          • FillExpiry     • DestOps        │  │
│  │  • TokenOut         • Qualification                   │  │
│  └───────────────────────────────────────────────────────┘  │
│                           ↓                                 │
├─────────────────────────────────────────────────────────────┤
│      CompactClaimPolicy       │     Permit2ClaimPolicy      │
│  ┌─────────────────────────┐  │  ┌─────────────────────────┐│
│  │ TokenIn: token+lockTag  │  │  │ TokenIn: token only     ││
│  │ Expiry = claimExpires   │  │  │ Expiry = deadline       ││
│  │ Uses Compact EIP-712    │  │  │ Uses Permit2 EIP-712    ││
│  └─────────────────────────┘  │  └─────────────────────────┘│
└─────────────────────────────────────────────────────────────┘

* "Expiry" refers to claimExpires (Compact) or deadline (Permit2)

//////////////////////////////////////////////////////////////*/

/*//////////////////////////////////////////////////////////////
                        MODE CONFIGURATION
//////////////////////////////////////////////////////////////

Each field has a 2-bit mode controlling how it's validated:

┌─────────────────────────────────────────────────────────────┐
│                    modeConfig (uint32)                      │
│                                                             │
│  Bits [31:18] = Reserved (unused)                           │
│  Bits [17:0]  = 9 fields × 2 bits each                      │
│                                                             │
│  ┌─────┬─────┬─────┬─────┬─────┬─────┬─────┬─────┬─────┐    │
│  │  Q  │ DO  │ OO  │ TO  │ FE  │ RC  │ TI  │ EX  │ AR  │    │
│  │17:16│15:14│13:12│11:10│ 9:8 │ 7:6 │ 5:4 │ 3:2 │ 1:0 │    │
│  └─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┘    │
│                                                             │
│  Field IDs:                                                 │
│  AR = Arbiter (0)        FE = FillExpiry (4)                │
│  EX = Expiry (1)         TO = TokenOut (5)                  │
│  TI = TokenIn (2)        OO = OriginOps (6)                 │
│  RC = Recipient (3)      DO = DestOps (7)                   │
│                          Q  = Qualification (8)             │
└─────────────────────────────────────────────────────────────┘

Mode values (2 bits each):
  00 (0) = SKIP            - Don't validate this field
  01 (1) = CHECK_STORAGE   - Validate against stored config (exact chainId)
  10 (2) = CHECK_CATCHALL  - Validate with chainId=0 fallback
  11 (3) = CHECK_SUBPOLICY - Delegate to external policy contract

//////////////////////////////////////////////////////////////*/

uint8 constant MODE_SKIP = 0;
uint8 constant MODE_CHECK_STORAGE = 1;
uint8 constant MODE_CHECK_CATCHALL = 2;
uint8 constant MODE_CHECK_SUBPOLICY = 3;

/*//////////////////////////////////////////////////////////////
                           FIELD IDS
//////////////////////////////////////////////////////////////*/

uint8 constant FIELD_ARBITER = 0;
uint8 constant FIELD_EXPIRY = 1;
uint8 constant FIELD_TOKEN_IN = 2;
uint8 constant FIELD_RECIPIENT = 3;
uint8 constant FIELD_FILL_EXPIRY = 4;
uint8 constant FIELD_TOKEN_OUT = 5;
uint8 constant FIELD_ORIGIN_OPS = 6;
uint8 constant FIELD_DEST_OPS = 7;
uint8 constant FIELD_QUALIFICATION = 8;

/*//////////////////////////////////////////////////////////////
                         PARAM RULES
//////////////////////////////////////////////////////////////

Used for qualification parameter validation. Supports complex
boolean expressions via an expression tree.

//////////////////////////////////////////////////////////////*/

/// @notice Stores the rules and their logical relationships
/// @param rootNodeIndex Index of the root node in the expression tree
/// @param rules Actual parameter rules to evaluate
/// @param packedNodes Bit-packed nodes of the expression tree
struct ParamRules {
    uint8 rootNodeIndex;
    ParamRule[] rules;
    uint256[] packedNodes;
}

/// @notice Defines a condition to check against a parameter
/// @dev Reads `length` bytes from `offset` and compares to `ref`
/// @param condition Type of comparison (EQUAL, GREATER_THAN, etc.)
/// @param offset Byte offset in calldata to read parameter
/// @param length Number of bytes to read (0 = 32 bytes)
/// @param ref Reference value to compare against
struct ParamRule {
    ParamCondition condition;
    uint64 offset;
    uint8 length;
    bytes32 ref;
}

/*//////////////////////////////////////////////////////////////
                        SUBPOLICY CONFIG
//////////////////////////////////////////////////////////////*/

/// @notice Configuration for delegating a field to an external policy
/// @param fieldId Which field this policy validates (0-8)
/// @param policyAddress Address of the I1271Policy contract
/// @param initData Initialization data passed to the sub-policy
struct SubPolicyConfig {
    uint8 fieldId;
    address policyAddress;
    bytes initData;
}

/*//////////////////////////////////////////////////////////////
                     STORAGE CONFIGURATIONS
//////////////////////////////////////////////////////////////

These structs define how field validation rules are stored.
Most fields support per-chain configuration with optional
catch-all (chainId=0) fallback.

//////////////////////////////////////////////////////////////*/

/// @notice Recipient configuration per target chain
/// @param targetChainId Target chain (0 for catch-all)
/// @param recipient Required recipient address
struct RecipientStorageConfig {
    uint256 targetChainId;
    address recipient;
}

/// @notice Fill expiry bounds per target chain
/// @dev Stored as packed uint256: lower 128 bits = min, upper 128 bits = max
/// @param targetChainId Target chain (0 for catch-all)
/// @param minFillExpiry Minimum allowed fill expiry timestamp
/// @param maxFillExpiry Maximum allowed fill expiry timestamp
struct FillExpiryStorageConfig {
    uint256 targetChainId;
    uint128 minFillExpiry;
    uint128 maxFillExpiry;
}

/// @notice Token output whitelist per target chain
/// @param targetChainId Target chain (0 for catch-all)
/// @param token Whitelisted output token address
struct TokenOutStorageConfig {
    uint256 targetChainId;
    address token;
}

/// @notice Origin operations requirement per chain
/// @param chainId Origin chain (0 for catch-all)
/// @param requireOriginOps If true, originOps must be present (non-empty)
struct OriginOpsStorageConfig {
    uint256 chainId;
    bool requireOriginOps;
}

/// @notice Destination operations requirement per target chain
/// @param targetChainId Target chain (0 for catch-all)
/// @param requireDestOps If true, destOps must be present (non-empty)
struct DestOpsStorageConfig {
    uint256 targetChainId;
    bool requireDestOps;
}

/// @notice Qualification parameter rules per chain and arbiter
/// @dev Qualification validation is per-arbiter because different
///      arbiters may have different qualification requirements
/// @param chainId Chain (0 for catch-all)
/// @param arbiter The arbiter these rules apply to
/// @param rules Parameter validation rules
struct QualificationStorageConfig {
    uint256 chainId;
    address arbiter;
    ParamRules rules;
}

/*//////////////////////////////////////////////////////////////
                         POLICY CONFIG TYPE
//////////////////////////////////////////////////////////////

Wraps uint32 for type safety. Contains 2-bit modes for 9 fields.

//////////////////////////////////////////////////////////////*/

/// @notice Wrapper type for mode configuration bitmap
/// @dev Provides type safety for the 32-bit mode configuration
type PolicyConfig is uint32;

using { neQConfig as != } for PolicyConfig global;
using { eqConfig as == } for PolicyConfig global;

/// @notice Inequality comparison for PolicyConfig
/// @param self The first PolicyConfig to compare
/// @param config The second PolicyConfig to compare
/// @return True if the configs are not equal
function neQConfig(PolicyConfig self, PolicyConfig config) pure returns (bool) {
    return PolicyConfig.unwrap(self) != PolicyConfig.unwrap(config);
}

/// @notice Equality comparison for PolicyConfig
/// @param self The first PolicyConfig to compare
/// @param config The second PolicyConfig to compare
/// @return True if the configs are equal
function eqConfig(PolicyConfig self, PolicyConfig config) pure returns (bool) {
    return PolicyConfig.unwrap(self) == PolicyConfig.unwrap(config);
}
