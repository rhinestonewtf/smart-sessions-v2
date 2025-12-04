// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Interfaces
import { I1271Policy } from "@smartsessions/interfaces/IPolicy.sol";

// Libraries
import { BaseStorageLib, BasePolicyStorage } from "@policies/claim/base/lib/BaseStorageLib.sol";
import { EnumerableSetLib } from "solady/utils/EnumerableSetLib.sol";

// Types
import { ParamCondition } from "@smartsessions/external/policies/ArgPolicy/ArgPolicy.sol";
import {
    ParamRules,
    ParamRule,
    QualificationRulesStorage,
    MODE_SKIP,
    MODE_CHECK_STORAGE,
    MODE_CHECK_CATCHALL,
    MODE_CHECK_SUBPOLICY,
    FIELD_ARBITER,
    FIELD_EXPIRY,
    FIELD_TOKEN_IN,
    FIELD_RECIPIENT,
    FIELD_FILL_EXPIRY,
    FIELD_TOKEN_OUT,
    FIELD_ORIGIN_OPS,
    FIELD_DEST_OPS,
    FIELD_QUALIFICATION,
    PolicyConfig,
    MASK_TARGET_CHECKS,
    MASK_MANDATE_CHECKS,
    FIELD_RECIPIENT_IS_SPONSOR
} from "@policies/claim/base/types/BaseDataTypes.sol";
import { ConfigId } from "@smartsessions/DataTypes.sol";

// forgefmt: disable-start
/// @title Base Config Library
/// @author Rhinestone
/// @notice Configuration decoding and initialization for ClaimPolicies
/// @dev Used by both CompactClaimPolicy and Permit2ClaimPolicy for common functionality.
/*//////////////////////////////////////////////////////////////
┌─────────────────────────────────────────────────────────────┐
│                    Design Principles                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. DIRECT STORAGE WRITES                                   │
│     - Read directly from calldata                           │
│     - Write directly to storage                             │
│     - No intermediate structs or arrays                     │
│                                                             │
│  2. DYNAMIC CALLDATA LAYOUT                                 │
│     - Fields only present if mode != SKIP                   │
│     - Order is fixed, presence is conditional               │
│     - Each function returns remaining calldata slice        │
│                                                             │
│  3. CALLDATA THREADING                                      │
│     - Pass calldata slice through each initializer          │
│     - Each function consumes its bytes, returns the rest    │
│     - Chain: data → init1 → remaining → init2 → ...         │
│                                                             │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│              Dynamic Calldata Layout                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  The calldata layout depends on modeConfig. Only fields     │
│  with mode != SKIP are present in the calldata.             │
│                                                             │
│  Example: modeConfig = 0x00000115                           │
│           AR=01 (storage), EX=01 (storage), TI=01 (storage) │
│           RC=00 (skip), FE=00 (skip), ...                   │
│                                                             │
│  Calldata for this config:                                  │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  [0:4]     modeConfig (0x00000115)                     │ │
│  │  [4:...]   arbiter config    ← AR=01, present          │ │
│  │  [...]     expiry config     ← EX=01, present          │ │
│  │  [...]     tokenIn config    ← TI=01, present          │ │
│  │  [...]     (end)             ← RC=00, FE=00 skipped    │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                             │
│  Different config = different layout:                       │
│  modeConfig = 0x00000141 (AR=01, RC=01, TO=01)              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  [0:4]     modeConfig (0x00000141)                     │ │
│  │  [4:...]   arbiter config    ← AR=01, present          │ │
│  │  [...]     recipient config  ← RC=01, present          │ │
│  │  [...]     tokenOut config   ← TO=01, present          │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                             │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│              Calldata Threading Pattern                     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Each initialize* function:                                 │
│  1. Reads its data from the START of the slice              │
│  2. Writes directly to storage                              │
│  3. Returns remaining slice (everything after its data)     │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │                   Full Calldata                     │    │
│  │  ┌────────┬────────┬────────┬────────┬────────┐     │    │
│  │  │ config │ arbiter│ expiry │tokenIn │recipnt │     │    │
│  │  └────────┴────────┴────────┴────────┴────────┘     │    │
│  └─────────────────────────────────────────────────────┘    │
│                         │                                   │
│                         ▼                                   │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  data = initData[4:]     // skip modeConfig         │    │
│  │  ┌────────┬────────┬────────┬────────┐              │    │
│  │  │ arbiter│ expiry │tokenIn │recipnt │              │    │
│  │  └────────┴────────┴────────┴────────┘              │    │
│  └─────────────────────────────────────────────────────┘    │
│                         │                                   │
│                         ▼                                   │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  data = initializeArbiter(data, $)                  │    │
│  │  ┌────────┬────────┬────────┐                       │    │
│  │  │ expiry │tokenIn │recipnt │  // arbiter consumed  │    │
│  │  └────────┴────────┴────────┘                       │    │
│  └─────────────────────────────────────────────────────┘    │
│                         │                                   │
│                         ▼                                   │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  data = initializeExpiry(data, $)                   │    │
│  │  ┌────────┬────────┐                                │    │
│  │  │tokenIn │recipnt │  // expiry consumed            │    │
│  │  └────────┴────────┘                                │    │
│  └─────────────────────────────────────────────────────┘    │
│                         │                                   │
│                         ▼                                   │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  data = initializeTokenIn(data, $)                  │    │
│  │  ┌────────┐                                         │    │
│  │  │recipnt │  // tokenIn consumed                    │    │
│  │  └────────┘                                         │    │
│  └─────────────────────────────────────────────────────┘    │
│                         │                                   │
│                         ▼                                   │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  data = initializeRecipient(data, $)                │    │
│  │  ┌┐                                                 │    │
│  │  ││  // empty, all consumed                         │    │
│  │  └┘                                                 │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                             │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                  Conditional Initialization                 │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  if (mode.isStorageMode()) {                                │
│      data = initialize*(data, $);  // consume + write       │
│  }                                                          │
│  // else: data unchanged, field not in calldata             │
│                                                             │
│  We only call initialize* if the mode indicates the field   │
│  data exists. The encoder must match: only include field    │
│  data for modes that require it.                            │
│                                                             │
└─────────────────────────────────────────────────────────────┘
//////////////////////////////////////////////////////////////*/
// forgefmt: disable-end
library BaseConfigLib {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using BaseStorageLib for *;
    using BaseConfigLib for *;
    using EnumerableSetLib for EnumerableSetLib.AddressSet;
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown when no qualification rules are set but qualification check is required
    error QualificationRulesNotSet();

    /// @notice Thrown when an invalid mode is provided
    error InvalidMode();

    /*//////////////////////////////////////////////////////////////
                             MODE EXTRACTION
    //////////////////////////////////////////////////////////////

    Extracts 2-bit mode values from the packed modeConfig.

    ┌─────────────────────────────────────────────────────────┐
    │  To extract mode for fieldId:                           │
    │  1. Shift right by (fieldId * 2) bits                   │
    │  2. Mask with 0x3 to get bottom 2 bits                  │
    │                                                         │
    │  Example: fieldId=3 (RECIPIENT)                         │
    │  modeConfig = 0b...XX_XX_XX_RC_TI_EX_AR                 │
    │  shift = 3 * 2 = 6                                      │
    │  (modeConfig >> 6) & 0x3 = RC                           │
    └─────────────────────────────────────────────────────────┘

    //////////////////////////////////////////////////////////////*/

    /// @notice Gets the 2-bit mode for a specific field from PolicyConfig
    /// @dev Extracts bits at position [fieldId*2 + 1 : fieldId*2]
    /// @param config The policy configuration wrapper
    /// @param fieldId The field ID (0-8, see FIELD_* constants)
    /// @return mode The 2-bit mode value (0=SKIP, 1=STORAGE, 2=CATCHALL, 3=SUBPOLICY)
    function getFieldMode(PolicyConfig config, uint8 fieldId) internal pure returns (uint8 mode) {
        uint32 modeConfig = PolicyConfig.unwrap(config);
        mode = uint8((modeConfig >> (fieldId * 2)) & 0x3);
    }

    /// @notice Sets the mode for a specific field in the mode configuration
    /// @dev Clears existing bits at field position, then sets new value
    /// @param modeConfig Current mode configuration bitmap
    /// @param fieldId The field ID (0-8, see FIELD_* constants)
    /// @param mode The new mode value (0-3)
    /// @return newConfig Updated mode configuration with new field mode
    function setFieldMode(
        uint32 modeConfig,
        uint8 fieldId,
        uint8 mode
    )
        internal
        pure
        returns (uint32 newConfig)
    {
        uint32 mask = ~(uint32(0x3) << (fieldId * 2));
        newConfig = (modeConfig & mask) | (uint32(mode) << (fieldId * 2));
    }

    /*//////////////////////////////////////////////////////////////
                             MODE PREDICATES
    //////////////////////////////////////////////////////////////*/

    /// @notice Checks if a mode requires storage initialization
    /// @dev Returns true for MODE_CHECK_STORAGE (1) or MODE_CHECK_CATCHALL (2)
    /// @param mode The mode value to check
    /// @return True if the mode uses storage-based validation
    function isStorageMode(uint8 mode) internal pure returns (bool) {
        return mode == MODE_CHECK_STORAGE || mode == MODE_CHECK_CATCHALL;
    }

    /// @notice Checks if a mode delegates validation to a sub-policy
    /// @dev Returns true only for MODE_CHECK_SUBPOLICY (3)
    /// @param mode The mode value to check
    /// @return True if the mode delegates to an external policy
    function isSubPolicyMode(uint8 mode) internal pure returns (bool) {
        return mode == MODE_CHECK_SUBPOLICY;
    }

    /// @notice Checks if validation is enabled for a field (mode != SKIP)
    /// @param config The policy configuration
    /// @param fieldId The field ID to check
    /// @return True if the field has any validation enabled
    function isEnabled(PolicyConfig config, uint8 fieldId) internal pure returns (bool) {
        return getFieldMode(config, fieldId) != MODE_SKIP;
    }

    /*//////////////////////////////////////////////////////////////
                          FIELD-SPECIFIC CHECKS
    //////////////////////////////////////////////////////////////*/

    /// @notice Checks if arbiter validation is enabled
    function hasCheckArbiter(PolicyConfig config) internal pure returns (bool) {
        return getFieldMode(config, FIELD_ARBITER) != MODE_SKIP;
    }

    /// @notice Checks if expiry validation is enabled
    function hasCheckExpiry(PolicyConfig config) internal pure returns (bool) {
        return getFieldMode(config, FIELD_EXPIRY) != MODE_SKIP;
    }

    /// @notice Checks if tokenIn validation is enabled
    function hasCheckTokenIn(PolicyConfig config) internal pure returns (bool) {
        return getFieldMode(config, FIELD_TOKEN_IN) != MODE_SKIP;
    }

    /// @notice Checks if recipient validation is enabled
    function hasCheckRecipient(PolicyConfig config) internal pure returns (bool) {
        return getFieldMode(config, FIELD_RECIPIENT) != MODE_SKIP;
    }

    /// @notice Checks if fillExpiry validation is enabled
    function hasCheckFillExpiry(PolicyConfig config) internal pure returns (bool) {
        return getFieldMode(config, FIELD_FILL_EXPIRY) != MODE_SKIP;
    }

    /// @notice Checks if tokenOut validation is enabled
    function hasCheckTokenOut(PolicyConfig config) internal pure returns (bool) {
        return getFieldMode(config, FIELD_TOKEN_OUT) != MODE_SKIP;
    }

    /// @notice Checks if originOps validation is enabled
    function hasCheckOriginOps(PolicyConfig config) internal pure returns (bool) {
        return getFieldMode(config, FIELD_ORIGIN_OPS) != MODE_SKIP;
    }

    /// @notice Checks if destOps validation is enabled
    function hasCheckDestOps(PolicyConfig config) internal pure returns (bool) {
        return getFieldMode(config, FIELD_DEST_OPS) != MODE_SKIP;
    }

    /// @notice Checks if qualification validation is enabled
    function hasCheckQualification(PolicyConfig config) internal pure returns (bool) {
        return getFieldMode(config, FIELD_QUALIFICATION) != MODE_SKIP;
    }

    /// @notice Checks if recipient-is-sponsor validation is enabled
    /// @dev When enabled, enforces recipient == sponsor with no storage lookup
    function hasCheckRecipientIsSponsor(PolicyConfig config) internal pure returns (bool) {
        return getFieldMode(config, FIELD_RECIPIENT_IS_SPONSOR) != MODE_SKIP;
    }

    /// @notice Check if any target-level validation is enabled
    function hasAnyTargetCheck(PolicyConfig config) internal pure returns (bool) {
        return (PolicyConfig.unwrap(config) & MASK_TARGET_CHECKS) != 0;
    }

    /// @notice Check if any mandate-level validation is enabled
    function hasAnyMandateCheck(PolicyConfig config) internal pure returns (bool) {
        return (PolicyConfig.unwrap(config) & MASK_MANDATE_CHECKS) != 0;
    }

    /*//////////////////////////////////////////////////////////////
                             CHAINID HELPERS
    //////////////////////////////////////////////////////////////*/

    // forgefmt: disable-start
    /// @notice Returns effective chainId for storage lookup based on mode
    /// @dev MODE_CHECK_CATCHALL uses chainId=0 as a wildcard that matches any chain.
    ///      MODE_CHECK_STORAGE requires exact chainId match.
    ///
    /// ┌─────────────────────────────────────────────────────────┐
    /// │  Mode Resolution:                                       │
    /// │  ┌─────────────────────────┬───────────────────────────┐│
    /// │  │ Mode                    │ Effective chainId         ││
    /// │  ├─────────────────────────┼───────────────────────────┤│
    /// │  │ MODE_CHECK_STORAGE      │ Returns actual chainId    ││
    /// │  │ MODE_CHECK_CATCHALL     │ Returns 0 (wildcard)      ││
    /// │  └─────────────────────────┴───────────────────────────┘│
    /// └─────────────────────────────────────────────────────────┘
    /// @param mode The field mode (should be STORAGE or CATCHALL)
    /// @param chainId The actual chain ID from the claim data
    /// @return effectiveChainId 0 if catch-all mode, otherwise the actual chainId
    // forgefmt: disable-end
    function getEffectiveChainId(
        uint8 mode,
        uint256 chainId
    )
        internal
        pure
        returns (uint256 effectiveChainId)
    {
        if (mode == MODE_CHECK_CATCHALL) {
            return 0;
        }
        return chainId;
    }

    /*//////////////////////////////////////////////////////////////
                           PACK/UNPACK HELPERS
    //////////////////////////////////////////////////////////////

    uint128 values are packed into uint256 for storage efficiency:

    ┌────────────────────────────────────────────────────────┐
    │                  Packed uint256                        │
    │  ┌────────────────────┬────────────────────┐           │
    │  │   upper (uint128)  │   lower (uint128)  │           │
    │  │   bits [255:128]   │   bits [127:0]     │           │
    │  └────────────────────┴────────────────────┘           │
    │                                                        │
    │  lower = typically min value                           │
    │  upper = typically max value                           │
    └────────────────────────────────────────────────────────┘

    //////////////////////////////////////////////////////////////*/

    /// @notice Packs two uint128 values into a single uint256
    /// @param lower Lower 128 bits value (typically min)
    /// @param upper Upper 128 bits value (typically max)
    /// @return packed The combined uint256 value
    function packUint128(uint128 lower, uint128 upper) internal pure returns (uint256 packed) {
        packed = uint256(lower) | (uint256(upper) << 128);
    }

    /// @notice Unpacks a uint256 into two uint128 values
    /// @param packed The combined uint256 value
    /// @return lower Lower 128 bits (bits [127:0])
    /// @return upper Upper 128 bits (bits [255:128])
    function unpackUint128(uint256 packed) internal pure returns (uint128 lower, uint128 upper) {
        lower = uint128(packed);
        upper = uint128(packed >> 128);
    }

    /*//////////////////////////////////////////////////////////////
                        MODE CONFIG INITIALIZATION
    /////////////////////////////////////////////////////////////*/

    /// @notice Decodes modeConfig and writes directly to storage
    /// @dev Check BaseDataTypes.sol for modeConfig layout
    /// @param $ Storage pointer to write modeConfig to
    /// @param initData Calldata starting with modeConfig (4 bytes)
    /// @return modeConfig The decoded policy configuration
    /// @return remaining Remaining calldata after modeConfig
    function initializeModeConfig(
        BasePolicyStorage storage $,
        bytes calldata initData
    )
        internal
        returns (PolicyConfig modeConfig, bytes calldata remaining)
    {
        modeConfig = PolicyConfig.wrap(uint32(bytes4(initData[0:4])));
        $.modeConfig = modeConfig;
        remaining = initData[4:];
    }

    /*//////////////////////////////////////////////////////////////
                          ARBITER INITIALIZATION
    //////////////////////////////////////////////////////////////

    Layout: [count: 1 byte][arbiters...]
    Entry:  [arbiter: 20 bytes] each

    ┌────────────────────────────────────────────────────────────┐
    │  Arbiter Config                                            │
    │  ┌──────────────────────────────────────────────────────┐  │
    │  │  count (uint8) - 1 byte                              │  │
    │  └──────────────────────────────────────────────────────┘  │
    │  ┌──────────────────────────────────────────────────────┐  │
    │  │  arbiter[0] (20 bytes)                               │  │
    │  ├──────────────────────────────────────────────────────┤  │
    │  │  arbiter[1] (20 bytes)                               │  │
    │  ├──────────────────────────────────────────────────────┤  │
    │  │  ... repeat for count entries ...                    │  │
    │  └──────────────────────────────────────────────────────┘  │
    └────────────────────────────────────────────────────────────┘

    Total size: 1 + (count × 20) bytes

    //////////////////////////////////////////////////////////////*/

    /// @notice Decodes arbiter addresses and writes directly to storage
    /// @dev Reads count followed by that many 20-byte addresses
    /// @param $ Storage pointer to write arbiters to
    /// @param initData Calldata starting with the arbiter config
    /// @return remaining Remaining calldata after all arbiters
    function initializeArbiter(
        BasePolicyStorage storage $,
        bytes calldata initData
    )
        internal
        returns (bytes calldata remaining)
    {
        // Read count
        uint8 count = uint8(initData[0]);
        // Initial offset after count
        uint256 offset = 1;
        // Read each arbiter address
        for (uint8 i = 0; i < count; i++) {
            // Store arbiter
            $.arbiterConfig.add(address(bytes20(initData[offset:offset + 20])));
            // Advance offset
            offset += 20;
        }
        // Return remaining data
        remaining = initData[offset:];
    }

    /*//////////////////////////////////////////////////////////////
                         EXPIRY INITIALIZATION
    //////////////////////////////////////////////////////////////

    Layout: [minExpiry: 16 bytes][maxExpiry: 16 bytes]

    ┌────────────────────────────────────────────────────────┐
    │  Expiry Config (32 bytes total)                        │
    │  ┌────────────────────┬────────────────────┐           │
    │  │  minExpiry (u128)  │  maxExpiry (u128)  │           │
    │  │  bytes [0:16]      │  bytes [16:32]     │           │
    │  └────────────────────┴────────────────────┘           │
    └────────────────────────────────────────────────────────┘

    //////////////////////////////////////////////////////////////*/

    /// @notice Decodes expiry bounds and writes directly to storage
    /// @param $ Storage pointer to write expiry to
    /// @param initData Calldata starting with expiry config
    /// @return remaining Remaining calldata after expiry config
    function initializeExpiry(
        BasePolicyStorage storage $,
        bytes calldata initData
    )
        internal
        returns (bytes calldata remaining)
    {
        $.expiryConfig = uint256(bytes32(initData[0:32]));
        remaining = initData[32:];
    }

    /*//////////////////////////////////////////////////////////////
                           RECIPIENT INITIALIZATION
    //////////////////////////////////////////////////////////////

    Layout: [count: 1 byte][entries...]
    Entry:  [targetChainId: 32 bytes][recipient: 20 bytes] = 52 bytes each

    The recipient config maps target chain IDs to recipient addresses.

    Special values:
    ┌─────────────────────────────────────────────────────────────┐
    │  ANY_ADDRESS (0xFFFF...FFFF)                                │
    │  ├── When stored as recipient, allows ANY recipient value   │
    │  └── Useful for "any recipient on whitelisted chains"       │
    └─────────────────────────────────────────────────────────────┘

    Note: For "recipient must equal sponsor" use case, prefer
    FIELD_RECIPIENT_IS_SPONSOR instead - it requires no storage
    lookups and is more gas efficient.

    ┌────────────────────────────────────────────────────────┐
    │  Recipient Config                                      │
    │  ┌────────────────────────────────────────────────┐    │
    │  │  count (uint8) - 1 byte                        │    │
    │  └────────────────────────────────────────────────┘    │
    │  ┌────────────────────────────────────────────────┐    │
    │  │  Entry (52 bytes):                             │    │
    │  │  ┌────────────────────┬────────────────────┐   │    │
    │  │  │ targetChainId (32) │ recipient (20)     │   │    │
    │  │  └────────────────────┴────────────────────┘   │    │
    │  └────────────────────────────────────────────────┘    │
    │  ... repeat for count entries ...                      │
    └────────────────────────────────────────────────────────┘

    Total size: 1 + (count × 52) bytes

    //////////////////////////////////////////////////////////////*/

    /// @notice Decodes recipient configs and writes directly to storage
    /// @param $ Storage pointer to write recipients to
    /// @param initData Calldata starting with recipient config
    /// @return remaining Remaining calldata after all recipient configs
    function initializeRecipient(
        BasePolicyStorage storage $,
        bytes calldata initData
    )
        internal
        returns (bytes calldata remaining)
    {
        // Read count
        uint8 count = uint8(initData[0]);
        // Initial offset after count
        uint256 offset = 1;
        // Read each recipient entry
        for (uint8 i = 0; i < count; i++) {
            // Read chainId and recipient address
            uint256 chainId = uint256(bytes32(initData[offset:offset + 32]));
            address recipient = address(bytes20(initData[offset + 32:offset + 52]));
            // Store recipient for chainId
            $.recipientConfig[chainId] = recipient;
            // Advance offset
            offset += 52;
        }
        // Return remaining data
        remaining = initData[offset:];
    }

    /*//////////////////////////////////////////////////////////////
                      FILL EXPIRY INITIALIZATION
    //////////////////////////////////////////////////////////////

    Layout: [count: 1 byte][entries...]
    Entry:  [targetChainId: 32][minFillExpiry: 16][maxFillExpiry: 16] = 64 bytes

    ┌────────────────────────────────────────────────────────┐
    │  FillExpiry Config                                     │
    │  ┌────────────────────────────────────────────────┐    │
    │  │  count (uint8) - 1 byte                        │    │
    │  └────────────────────────────────────────────────┘    │
    │  ┌────────────────────────────────────────────────┐    │
    │  │  Entry (64 bytes):                             │    │
    │  │  ┌─────────────┬─────────────┬─────────────┐   │    │
    │  │  │ chainId(32) │ min(16)     │ max(16)     │   │    │
    │  │  └─────────────┴─────────────┴─────────────┘   │    │
    │  └────────────────────────────────────────────────┘    │
    │  ... repeat for count entries ...                      │
    └────────────────────────────────────────────────────────┘

    Total size: 1 + (count × 64) bytes

    //////////////////////////////////////////////////////////////*/

    /// @notice Decodes fill expiry configs and writes directly to storage
    /// @param $ Storage pointer to write fill expiry to
    /// @param initData Calldata starting with fill expiry config
    /// @return remaining Remaining calldata after all fill expiry configs
    function initializeFillExpiry(
        BasePolicyStorage storage $,
        bytes calldata initData
    )
        internal
        returns (bytes calldata remaining)
    {
        // Read count
        uint8 count = uint8(initData[0]);
        // Initial offset after count
        uint256 offset = 1;
        // Read each fill expiry entry
        for (uint8 i = 0; i < count; i++) {
            // Read chainId, minFillExpiry, maxFillExpiry
            uint256 chainId = uint256(bytes32(initData[offset:offset + 32]));
            $.fillExpiryConfig[chainId] = uint256(bytes32(initData[offset + 32:offset + 64]));
            // Advance offset
            offset += 64;
        }
        // Return remaining data
        remaining = initData[offset:];
    }

    /*//////////////////////////////////////////////////////////////
                       TOKEN OUT INITIALIZATION
    //////////////////////////////////////////////////////////////

    Layout: [count: 1 byte][entries...]
    Entry:  [targetChainId: 32 bytes][token: 20 bytes] = 52 bytes each

    ┌────────────────────────────────────────────────────────┐
    │  TokenOut Config                                       │
    │  ┌────────────────────────────────────────────────┐    │
    │  │  count (uint8) - 1 byte                        │    │
    │  └────────────────────────────────────────────────┘    │
    │  ┌────────────────────────────────────────────────┐    │
    │  │  Entry (52 bytes):                             │    │
    │  │  ┌────────────────────┬────────────────────┐   │    │
    │  │  │ targetChainId (32) │ token (20)         │   │    │
    │  │  └────────────────────┴────────────────────┘   │    │
    │  └────────────────────────────────────────────────┘    │
    │  ... repeat for count entries ...                      │
    └────────────────────────────────────────────────────────┘

    Total size: 1 + (count × 52) bytes

    //////////////////////////////////////////////////////////////*/

    /// @notice Decodes token out configs and writes directly to storage
    /// @param $ Storage pointer to write token out to
    /// @param initData Calldata starting with token out config
    /// @return remaining Remaining calldata after all token out configs
    function initializeTokenOut(
        BasePolicyStorage storage $,
        bytes calldata initData
    )
        internal
        returns (bytes calldata remaining)
    {
        // Read count
        uint8 count = uint8(initData[0]);
        // Initial offset after count
        uint256 offset = 1;
        // Read each token out entry
        for (uint8 i = 0; i < count; i++) {
            // Read chainId and token address
            uint256 chainId = uint256(bytes32(initData[offset:offset + 32]));
            address token = address(bytes20(initData[offset + 32:offset + 52]));
            // Store token for chainId
            $.tokenOutSet[chainId].add(token);
            // Advance offset
            offset += 52;
        }
        // Return remaining data
        remaining = initData[offset:];
    }

    /*//////////////////////////////////////////////////////////////
                       ORIGIN OPS INITIALIZATION
    //////////////////////////////////////////////////////////////

    Layout: [count: 1 byte][entries...]
    Entry:  [chainId: 32 bytes][requireOriginOps: 1 byte] = 33 bytes each

    ┌────────────────────────────────────────────────────────┐
    │  OriginOps Config                                      │
    │  ┌────────────────────────────────────────────────┐    │
    │  │  count (uint8) - 1 byte                        │    │
    │  └────────────────────────────────────────────────┘    │
    │  ┌────────────────────────────────────────────────┐    │
    │  │  Entry (33 bytes):                             │    │
    │  │  ┌────────────────────┬─────────────────────┐  │    │
    │  │  │ chainId (32)       │ required (1)        │  │    │
    │  │  └────────────────────┴─────────────────────┘  │    │
    │  └────────────────────────────────────────────────┘    │
    │  ... repeat for count entries ...                      │
    └────────────────────────────────────────────────────────┘

    Total size: 1 + (count × 33) bytes

    //////////////////////////////////////////////////////////////*/

    /// @notice Decodes origin ops configs and writes directly to storage
    /// @param $ Storage pointer to write origin ops to
    /// @param initData Calldata starting with origin ops config
    /// @return remaining Remaining calldata after all origin ops configs
    function initializeOriginOps(
        BasePolicyStorage storage $,
        bytes calldata initData
    )
        internal
        returns (bytes calldata remaining)
    {
        // Read count
        uint8 count = uint8(initData[0]);
        // Initial offset after count
        uint256 offset = 1;
        // Read each origin ops entry
        for (uint8 i = 0; i < count; i++) {
            // Read chainId and required flag
            uint256 chainId = uint256(bytes32(initData[offset:offset + 32]));
            bool required = uint8(initData[offset + 32]) != 0;
            // Store origin ops requirement for chainId
            $.originOpsConfig[chainId] = required;
            // Advance offset
            offset += 33;
        }
        // Return remaining data
        remaining = initData[offset:];
    }

    /*//////////////////////////////////////////////////////////////
                        DEST OPS INITIALIZATION
    //////////////////////////////////////////////////////////////

    Layout: [count: 1 byte][entries...]
    Entry:  [targetChainId: 32 bytes][requireDestOps: 1 byte] = 33 bytes each

    ┌────────────────────────────────────────────────────────┐
    │  DestOps Config                                        │
    │  ┌────────────────────────────────────────────────┐    │
    │  │  count (uint8) - 1 byte                        │    │
    │  └────────────────────────────────────────────────┘    │
    │  ┌────────────────────────────────────────────────┐    │
    │  │  Entry (33 bytes):                             │    │
    │  │  ┌────────────────────┬─────────────────────┐  │    │
    │  │  │ targetChainId (32) │ required (1)        │  │    │
    │  │  └────────────────────┴─────────────────────┘  │    │
    │  └────────────────────────────────────────────────┘    │
    │  ... repeat for count entries ...                      │
    └────────────────────────────────────────────────────────┘

    Total size: 1 + (count × 33) bytes

    //////////////////////////////////////////////////////////////*/

    /// @notice Decodes dest ops configs and writes directly to storage
    /// @param $ Storage pointer to write dest ops to
    /// @param initData Calldata starting with dest ops config
    /// @return remaining Remaining calldata after all dest ops configs
    function initializeDestOps(
        BasePolicyStorage storage $,
        bytes calldata initData
    )
        internal
        returns (bytes calldata remaining)
    {
        // Read count
        uint8 count = uint8(initData[0]);
        // Initial offset after count
        uint256 offset = 1;
        // Read each dest ops entry
        for (uint8 i = 0; i < count; i++) {
            // Read chainId and required flag
            uint256 chainId = uint256(bytes32(initData[offset:offset + 32]));
            bool required = uint8(initData[offset + 32]) != 0;
            // Store dest ops requirement for chainId
            $.destOpsConfig[chainId] = required;
            // Advance offset
            offset += 33;
        }
        // Return remaining data
        remaining = initData[offset:];
    }

    /*//////////////////////////////////////////////////////////////
                     QUALIFICATION INITIALIZATION
    //////////////////////////////////////////////////////////////

    Layout: [count: 1 byte][entries...]
    Entry (variable size):
      [chainId: 32][arbiter: 20][useArbiterHash: 1][rootNodeIndex: 1]
      [ruleCount: 1][rules...][packedNodesCount: 1][packedNodes...]

    Rule (42 bytes each):
      [condition: 1][offset: 8][length: 1][ref: 32]

    PackedNode (32 bytes each):
      [node: 32]

    ┌────────────────────────────────────────────────────────┐
    │  Qualification Config                                  │
    │  ┌────────────────────────────────────────────────┐    │
    │  │  count (uint8) - 1 byte                        │    │
    │  └────────────────────────────────────────────────┘    │
    │  ┌────────────────────────────────────────────────┐    │
    │  │  Entry (variable):                             │    │
    │  │  ┌─────────────────────────────────────────┐   │    │
    │  │  │ chainId (32) | arbiter (20) |           │   │    │
    │  │  │ useArbiterHash (1) | rootNodeIndex (1)  │   │    │
    │  │  ├─────────────────────────────────────────┤   │    │
    │  │  │ ruleCount (1)                           │   │    │
    │  │  │ Rule: [cond(1)|off(8)|len(1)|ref(32)]   │   │    │
    │  │  │ ... more rules ...                      │   │    │
    │  │  ├─────────────────────────────────────────┤   │    │
    │  │  │ packedNodesCount (1)                    │   │    │
    │  │  │ PackedNode: [node (32)]                 │   │    │
    │  │  │ ... more nodes ...                      │   │    │
    │  │  └─────────────────────────────────────────┘   │    │
    │  └────────────────────────────────────────────────┘    │
    └────────────────────────────────────────────────────────┘

    //////////////////////////////////////////////////////////////*/

    /// @notice Decodes qualification configs and writes directly to storage
    /// @dev Each entry contains an expression tree for validating qualification data
    /// @param $ Storage pointer to write qualification to
    /// @param initData Calldata starting with qualification config
    /// @return remaining Remaining calldata after all qualification configs
    function initializeQualification(
        BasePolicyStorage storage $,
        bytes calldata initData
    )
        internal
        returns (bytes calldata remaining)
    {
        // Read count
        uint8 count = uint8(initData[0]);
        // Initial offset after count
        uint256 offset = 1;
        // Read each qualification entry
        for (uint8 j = 0; j < count; j++) {
            // Decode chainId (32 bytes)
            uint256 chainId = uint256(bytes32(initData[offset:offset + 32]));
            offset += 32;

            // Decode arbiter address (20 bytes)
            address arbiter = address(bytes20(initData[offset:offset + 20]));
            offset += 20;

            // Decode useArbiterHash flag (1 byte)
            bool useArbiterHash = uint8(initData[offset]) != 0;
            offset += 1;

            // Decode root node index (1 byte)
            uint8 rootNodeIndex = uint8(initData[offset]);
            offset += 1;

            // Decode rule count (32 bytes)
            uint8 ruleCount = uint8(initData[offset]);
            offset += 1;

            // Decode each rule (42 bytes each)
            ParamRule[] memory paramRules = new ParamRule[](ruleCount);
            for (uint8 i = 0; i < ruleCount; i++) {
                paramRules[i] = ParamRule({
                    condition: ParamCondition(uint8(initData[offset])),
                    offset: uint64(bytes8(initData[offset + 1:offset + 9])),
                    length: uint8(initData[offset + 9]),
                    ref: bytes32(initData[offset + 10:offset + 42])
                });
                offset += 42;
            }

            // Decode packed nodes count (32 bytes)
            uint8 packedNodesLength = uint8(initData[offset]);
            offset += 1;

            // Decode each packed node (32 bytes each)
            uint256[] memory packedNodes = new uint256[](packedNodesLength);
            for (uint8 i = 0; i < packedNodesLength; i++) {
                packedNodes[i] = uint256(bytes32(initData[offset:offset + 32]));
                offset += 32;
            }

            // Make sure there are rules defined
            require(ruleCount != 0 && packedNodesLength != 0, QualificationRulesNotSet());

            // Write to storage
            $.qualificationConfig[chainId][arbiter] = QualificationRulesStorage({
                useArbiterHash: useArbiterHash,
                rules: ParamRules({
                    rootNodeIndex: rootNodeIndex, rules: paramRules, packedNodes: packedNodes
                })
            });
        }

        remaining = initData[offset:];
    }

    /*//////////////////////////////////////////////////////////////
                      SUB-POLICIES INITIALIZATION
    //////////////////////////////////////////////////////////////

    Layout: [count: 1 byte][entries...]
    Entry (variable size):
      [fieldId: 1][policyAddress: 20][initDataLength: 32][initData: variable]

    ┌────────────────────────────────────────────────────────────┐
    │  SubPolicy Config                                          │
    │  ┌────────────────────────────────────────────────────┐    │
    │  │  count (uint8) - 1 byte                            │    │
    │  └────────────────────────────────────────────────────┘    │
    │  ┌────────────────────────────────────────────────────┐    │
    │  │  Entry (variable):                                 │    │
    │  │  ┌─────────────────────────────────────────────┐   │    │
    │  │  │ fieldId (1) | policyAddress (20)            │   │    │
    │  │  ├─────────────────────────────────────────────┤   │    │
    │  │  │ initDataLength (32)                         │   │    │
    │  │  ├─────────────────────────────────────────────┤   │    │
    │  │  │ initData (initDataLength bytes)             │   │    │
    │  │  └─────────────────────────────────────────────┘   │    │
    │  └────────────────────────────────────────────────────┘    │
    │  ... repeat for count entries ...                          │
    └────────────────────────────────────────────────────────────┘

    //////////////////////////////////////////////////////////////*/

    /// @notice Decodes sub-policy configs, writes addresses to storage, and initializes each
    /// @dev Reads directly from calldata - no memory allocation needed
    /// @param $ Storage pointer to write sub-policy addresses to
    /// @param initData Calldata starting with sub-policy config
    /// @param modeConfig The policy configuration for mode validation
    /// @param account The account being configured
    /// @param configId The configuration ID
    /// @return remaining Remaining calldata after all sub-policy configs
    function initializeSubPolicies(
        BasePolicyStorage storage $,
        bytes calldata initData,
        PolicyConfig modeConfig,
        address account,
        ConfigId configId
    )
        internal
        returns (bytes calldata remaining)
    {
        // Read count
        uint8 count = uint8(initData[0]);
        // Initial offset after count
        uint256 offset = 1;

        // Read and initialize each sub-policy entry
        for (uint8 i = 0; i < count; i++) {
            // Decode fieldId (1 byte)
            uint8 fieldId = uint8(initData[offset]);
            offset += 1;

            // Validate mode is SUBPOLICY
            require(modeConfig.getFieldMode(fieldId) == MODE_CHECK_SUBPOLICY, InvalidMode());

            // Decode policy address (20 bytes)
            address policyAddress = address(bytes20(initData[offset:offset + 20]));
            offset += 20;

            // Write policy address to storage
            $.subPolicies[fieldId] = policyAddress;

            // Decode init data length (32 bytes)
            uint256 initDataLength = uint256(bytes32(initData[offset:offset + 32]));
            offset += 32;

            // Initialize sub-policy with calldata slice
            I1271Policy(policyAddress)
                .initializeWithMultiplexer(
                    account, configId, initData[offset:offset + initDataLength]
                );
            offset += initDataLength;
        }

        // Return remaining data
        remaining = initData[offset:];
    }
}
