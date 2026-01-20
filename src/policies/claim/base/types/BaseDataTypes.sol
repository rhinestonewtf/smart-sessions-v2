// SPDX-License-Identifier: BUSL-1.1
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
│  Bits [31:20] = Reserved (unused)                           │
│  Bits [19:0]  = 10 fields × 2 bits each                     │
│                                                             │
│ ┌─────┬─────┬─────┬─────┬─────┬─────┬─────┬─────┬─────┬────┐│
│ │ RIS │  Q  │ DO  │ OO  │ TO  │ FE  │ RC  │ TI  │ EX  │ AR ││
│ │19:18│17:16│15:14│13:12│11:10│ 9:8 │ 7:6 │ 5:4 │ 3:2 │ 1:0││
│ └─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┴────┘│
│                                                             │
│  Field IDs:                                                 │
│  AR  = Arbiter (0)           FE  = FillExpiry (4)           │
│  EX  = Expiry (1)            TO  = TokenOut (5)             │
│  TI  = TokenIn (2)           OO  = OriginOps (6)            │
│  RC  = Recipient (3)         DO  = DestOps (7)              │
│                              Q   = Qualification (8)        │
│                              RIS = RecipientIsSponsor (9)   │
└─────────────────────────────────────────────────────────────┘

Mode values (2 bits each):
  00 (0) = SKIP            - Don't validate this field
  01 (1) = CHECK_STORAGE   - Validate against stored config (exact chainId)
  10 (2) = CHECK_CATCHALL  - Validate with chainId=0 fallback
  11 (3) = CHECK_SUBPOLICY - Delegate to external policy contract

Special case - FIELD_RECIPIENT_IS_SPONSOR:
  This field only uses mode != SKIP as a flag. When enabled (any non-zero
  mode), it enforces that recipient == sponsor (the account). No storage
  or init data is required - just a single comparison against the sponsor
  address already in memory. This is useful for "bridge to self" sessions.

//////////////////////////////////////////////////////////////*/

uint8 constant MODE_SKIP = 0;
uint8 constant MODE_CHECK_STORAGE = 1;
uint8 constant MODE_CHECK_CATCHALL = 2;
uint8 constant MODE_CHECK_SUBPOLICY = 3;

/*//////////////////////////////////////////////////////////////
                           FIELD IDS
//////////////////////////////////////////////////////////////*/

uint8 constant FIELD_ARBITER = 0;
uint8 constant FIELD_EXPIRY = 1; // claimExpires (Compact) or deadline (Permit2)
uint8 constant FIELD_TOKEN_IN = 2;
uint8 constant FIELD_RECIPIENT = 3;
uint8 constant FIELD_FILL_EXPIRY = 4;
uint8 constant FIELD_TOKEN_OUT = 5;
uint8 constant FIELD_ORIGIN_OPS = 6;
uint8 constant FIELD_DEST_OPS = 7;
uint8 constant FIELD_QUALIFICATION = 8;
uint8 constant FIELD_RECIPIENT_IS_SPONSOR = 9;

/*//////////////////////////////////////////////////////////////
                        MODE CHECK MASKS
//////////////////////////////////////////////////////////////*/

// Mask for target fields: recipient (bits 6-7), fillExpiry (bits 8-9), tokenOut (bits 10-11),
// recipientIsSponsor (bits 18-19)
uint32 constant MASK_TARGET_CHECKS =
    uint32(0x3) << 6 | uint32(0x3) << 8 | uint32(0x3) << 10 | uint32(0x3) << 18;
// = 0xC0FC0

// Mask for mandate fields: target fields + originOps (12-13) + destOps (14-15) + qualification
// (16-17)
uint32 constant MASK_MANDATE_CHECKS =
    MASK_TARGET_CHECKS | uint32(0x3) << 12 | uint32(0x3) << 14 | uint32(0x3) << 16;

// = 0x3FFC0

/*//////////////////////////////////////////////////////////////
                           SENTINELS
//////////////////////////////////////////////////////////////

Special address values used as configuration wildcards.

┌─────────────────────────────────────────────────────────────┐
│                    ANY_ADDRESS Sentinel                     │
│                                                             │
│  Value: 0xFFfFfFffFFfffFFfFFfFFFFFffFFFffffFfFFFfF          │
│                                                             │
│  When used as a stored recipient address, validation will   │
│  pass for ANY recipient value. This allows configuring a    │
│  session that permits bridging to any address on a given    │
│  target chain, without restricting the specific recipient.  │
│                                                             │
│  Example usage in init data:                                │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  chainId: 137                                          │ │
│  │  recipient: 0xFFFF...FFFF  ← allows any recipient      │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                             │
│  This is useful when you want to:                           │
│  • Lock the arbiter, tokens, and chain but allow flexible   │
│    recipient selection                                      │
│  • Allow the session to send to any address on specific     │
│    whitelisted destination chains                           │
└─────────────────────────────────────────────────────────────┘

//////////////////////////////////////////////////////////////*/

// Sentinel value allowing any address
address constant ANY_ADDRESS = 0xFFfFfFffFFfffFFfFFfFFFFFffFFFffffFfFFFfF;

/*//////////////////////////////////////////////////////////////
                         PARAM RULES
//////////////////////////////////////////////////////////////

Used for qualification parameter validation. Supports complex
boolean expressions via an expression tree.

Expression Tree Node Format (uint256):
┌─────────────────────────────────────────────────────────────┐
│  Bits [7:6] = Node Type                                     │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ 00 = RULE node  → Bits [5:0] = rule index            │   │
│  │ 01 = NOT node   → Bits [5:0] = child node index      │   │
│  │ 10 = AND node   → Bits [5:0] = left, [13:8] = right  │   │
│  │ 11 = OR node    → Bits [5:0] = left, [13:8] = right  │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘

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

// forgefmt: disable-start
/// @notice Defines a condition to check against a parameter
/// @dev Reads `length` bytes from `offset` and compares to `ref`
///
/// ┌─────────────────────────────────────────────────────────┐
/// │                    Calldata Layout                      │
/// │  ┌──────────┬──────────────────────┬──────────────────┐ │
/// │  │ ...      │  param (length bytes) │     ...         │ │
/// │  │          │  ↑ offset             │                 │ │
/// │  └──────────┴──────────────────────┴──────────────────┘ │
/// │                                                         │
/// │  If length == 0, reads full 32 bytes from offset        │
/// └─────────────────────────────────────────────────────────┘
///
/// @param condition Type of comparison (EQUAL, GREATER_THAN, etc.)
/// @param offset Byte offset in calldata to read parameter
/// @param length Number of bytes to read (0 = 32 bytes)
/// @param ref Reference value to compare against
// forgefmt: disable-end
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
                     QUALIFICATION STORAGE
//////////////////////////////////////////////////////////////*/

/// @notice Stored qualification configuration
/// @param useArbiterHash If true, use arbiter.qualificationHash() for hashing
/// @param rules Parameter validation rules
struct QualificationRulesStorage {
    bool useArbiterHash;
    ParamRules rules;
}

/*//////////////////////////////////////////////////////////////
                         POLICY CONFIG TYPE
//////////////////////////////////////////////////////////////

Wraps uint32 for type safety. Contains 2-bit modes for 9 fields.

//////////////////////////////////////////////////////////////*/

/// @dev Empty PolicyConfig constant (all modes set to SKIP)
PolicyConfig constant EMPTY_CONFIG = PolicyConfig.wrap(0);

/// @notice Wrapper type for mode configuration bitmap
/// @dev Provides type safety for the 32-bit mode configuration
type PolicyConfig is uint32;

using { neqConfig as != } for PolicyConfig global;
using { eqConfig as == } for PolicyConfig global;

/// @notice Inequality comparison for PolicyConfig
/// @param self The first PolicyConfig to compare
/// @param config The second PolicyConfig to compare
/// @return True if the configs are not equal
function neqConfig(PolicyConfig self, PolicyConfig config) pure returns (bool) {
    return PolicyConfig.unwrap(self) != PolicyConfig.unwrap(config);
}

/// @notice Equality comparison for PolicyConfig
/// @param self The first PolicyConfig to compare
/// @param config The second PolicyConfig to compare
/// @return True if the configs are equal
function eqConfig(PolicyConfig self, PolicyConfig config) pure returns (bool) {
    return PolicyConfig.unwrap(self) == PolicyConfig.unwrap(config);
}

