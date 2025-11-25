// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Libraries
import { BaseStorageLib } from "@policies/claim/base/lib/BaseStorageLib.sol";

// Types
import { ParamCondition } from "@smartsessions/external/policies/ArgPolicy/ArgPolicy.sol";
import {
    ParamRules,
    ParamRule,
    SubPolicyConfig,
    RecipientStorageConfig,
    FillExpiryStorageConfig,
    TokenOutStorageConfig,
    OriginOpsStorageConfig,
    DestOpsStorageConfig,
    QualificationStorageConfig,
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
    PolicyConfig
} from "@policies/claim/base/types/BaseDataTypes.sol";

/*//////////////////////////////////////////////////////////////
                      INIT DATA STRUCTURE
//////////////////////////////////////////////////////////////

Decoded initialization data for shared fields (protocol-specific
fields like tokenIn are handled by protocol-specific config libs).

//////////////////////////////////////////////////////////////*/

/// @notice Decoded initialization data for base fields
/// @dev TokenIn configs are NOT included here - see protocol-specific InitData
struct BaseInitData {
    /// @notice The mode configuration bitmap (passed through for reference)
    PolicyConfig modeConfig;
    /// @notice Required arbiter address
    address arbiter;
    /// @notice Minimum expiry value (claimExpires or deadline)
    uint128 minExpiry;
    /// @notice Maximum expiry value
    uint128 maxExpiry;
    /// @notice Per-chain recipient configurations
    RecipientStorageConfig[] recipientConfigs;
    /// @notice Per-chain fill expiry configurations
    FillExpiryStorageConfig[] fillExpiryConfigs;
    /// @notice Per-chain token output whitelists
    TokenOutStorageConfig[] tokenOutConfigs;
    /// @notice Per-chain origin ops requirements
    OriginOpsStorageConfig[] originOpsConfigs;
    /// @notice Per-chain dest ops requirements
    DestOpsStorageConfig[] destOpsConfigs;
    /// @notice Per-chain-per-arbiter qualification rules
    QualificationStorageConfig[] qualificationConfigs;
    /// @notice Sub-policy configurations
    SubPolicyConfig[] subPolicies;
}

/// @title Base Config Library
/// @author Rhinestone
/// @notice Shared configuration decoding and mode extraction for ClaimPolicies
/// @dev Used by both CompactClaimPolicy and Permit2ClaimPolicy for common functionality
library BaseConfigLib {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using BaseStorageLib for *;
    using BaseConfigLib for *;

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
    function getFieldMode(
        PolicyConfig config,
        uint8 fieldId
    )
        internal
        pure
        returns (uint8 mode)
    {
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
        // Create mask with 0s at field position, 1s elsewhere
        uint32 mask = ~(uint32(0x3) << (fieldId * 2));
        // Clear field bits and set new value
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
    /// @dev A field with MODE_SKIP is not validated at all
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
    /// @param config The policy configuration
    /// @return True if arbiter field has validation enabled (mode != SKIP)
    function hasCheckArbiter(PolicyConfig config) internal pure returns (bool) {
        return getFieldMode(config, FIELD_ARBITER) != MODE_SKIP;
    }

    /// @notice Checks if expiry validation is enabled
    /// @dev Expiry refers to claimExpires (Compact) or deadline (Permit2)
    /// @param config The policy configuration
    /// @return True if expiry field has validation enabled (mode != SKIP)
    function hasCheckExpiry(PolicyConfig config) internal pure returns (bool) {
        return getFieldMode(config, FIELD_EXPIRY) != MODE_SKIP;
    }

    /// @notice Checks if tokenIn validation is enabled
    /// @param config The policy configuration
    /// @return True if tokenIn field has validation enabled (mode != SKIP)
    function hasCheckTokenIn(PolicyConfig config) internal pure returns (bool) {
        return getFieldMode(config, FIELD_TOKEN_IN) != MODE_SKIP;
    }

    /// @notice Checks if recipient validation is enabled
    /// @param config The policy configuration
    /// @return True if recipient field has validation enabled (mode != SKIP)
    function hasCheckRecipient(PolicyConfig config) internal pure returns (bool) {
        return getFieldMode(config, FIELD_RECIPIENT) != MODE_SKIP;
    }

    /// @notice Checks if fillExpiry validation is enabled
    /// @param config The policy configuration
    /// @return True if fillExpiry field has validation enabled (mode != SKIP)
    function hasCheckFillExpiry(PolicyConfig config) internal pure returns (bool) {
        return getFieldMode(config, FIELD_FILL_EXPIRY) != MODE_SKIP;
    }

    /// @notice Checks if tokenOut validation is enabled
    /// @param config The policy configuration
    /// @return True if tokenOut field has validation enabled (mode != SKIP)
    function hasCheckTokenOut(PolicyConfig config) internal pure returns (bool) {
        return getFieldMode(config, FIELD_TOKEN_OUT) != MODE_SKIP;
    }

    /// @notice Checks if originOps validation is enabled
    /// @param config The policy configuration
    /// @return True if originOps field has validation enabled (mode != SKIP)
    function hasCheckOriginOps(PolicyConfig config) internal pure returns (bool) {
        return getFieldMode(config, FIELD_ORIGIN_OPS) != MODE_SKIP;
    }

    /// @notice Checks if destOps validation is enabled
    /// @param config The policy configuration
    /// @return True if destOps field has validation enabled (mode != SKIP)
    function hasCheckDestOps(PolicyConfig config) internal pure returns (bool) {
        return getFieldMode(config, FIELD_DEST_OPS) != MODE_SKIP;
    }

    /// @notice Checks if qualification validation is enabled
    /// @param config The policy configuration
    /// @return True if qualification field has validation enabled (mode != SKIP)
    function hasCheckQualification(PolicyConfig config) internal pure returns (bool) {
        return getFieldMode(config, FIELD_QUALIFICATION) != MODE_SKIP;
    }

    /*//////////////////////////////////////////////////////////////
                             CHAINID HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Returns effective chainId for storage lookup based on mode
    /// @dev MODE_CHECK_CATCHALL uses chainId=0 as a wildcard that matches any chain.
    ///      MODE_CHECK_STORAGE requires exact chainId match.
    ///
    /// ┌────────────────────────────────────────────────────────┐
    /// │  Mode Resolution:                                      │
    /// │                                                        │
    /// ┌─────────────────────────┬──────────────────────────────┐
    /// │  │ Mode                 │ Effective chainId            │
    /// │  │ MODE_CHECK_STORAGE   │ Returns actual chainId       │
    /// │  │ MODE_CHECK_CATCHALL  │ Returns 0 (wildcard)         │
    /// └─────────────────────────┴──────────────────────────────┘
    /// └────────────────────────────────────────────────────────┘
    ///
    /// @param mode The field mode (should be STORAGE or CATCHALL)
    /// @param chainId The actual chain ID from the claim data
    /// @return effectiveChainId 0 if catch-all mode, otherwise the actual chainId
    function getEffectiveChainId(
        uint8 mode,
        uint256 chainId
    )
        internal
        pure
        returns (uint256 effectiveChainId)
    {
        // In catch-all mode, use chainId=0 for storage lookup
        if (mode == MODE_CHECK_CATCHALL) {
            return 0;
        }
        // Otherwise, use the actual chainId
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
    /// @dev Lower value occupies bits [127:0], upper occupies bits [255:128]
    /// @param lower Lower 128 bits value (typically min)
    /// @param upper Upper 128 bits value (typically max)
    /// @return packed The combined uint256 value
    function packUint128(uint128 lower, uint128 upper) internal pure returns (uint256 packed) {
        packed = uint256(lower) | (uint256(upper) << 128);
    }

    /// @notice Unpacks a uint256 into two uint128 values
    /// @dev Inverse of packUint128
    /// @param packed The combined uint256 value
    /// @return lower Lower 128 bits (bits [127:0])
    /// @return upper Upper 128 bits (bits [255:128])
    function unpackUint128(uint256 packed) internal pure returns (uint128 lower, uint128 upper) {
        lower = uint128(packed);
        upper = uint128(packed >> 128);
    }

    /*//////////////////////////////////////////////////////////////
                         ARBITER CONFIG DECODING
    //////////////////////////////////////////////////////////////

    Layout: [count: 32 bytes][arbiters...]
    Entry:  [arbiter: 20 bytes] each

    ┌────────────────────────────────────────────────────────────┐
    │  Arbiter Config                                            │
    │  ┌──────────────────────────────────────────────────────┐  │
    │  │  count (uint256) - 32 bytes                          │  │
    │  └──────────────────────────────────────────────────────┘  │
    │  ┌──────────────────────────────────────────────────────┐  │
    │  │  arbiter (20 bytes)                                  │  │
    │  └──────────────────────────────────────────────────────┘  │
    │  ... repeat for count entries ...                          │
    └────────────────────────────────────────────────────────────┘

    Total size: 32 + (count * 20) bytes

    //////////////////////////////////////////////////////////////*/

    /// @notice Decodes arbiter addresses from initialization data
    /// @dev Reads count followed by that many 20-byte addresses
    /// @param initData Calldata starting with the arbiter config
    /// @return arbiters Array of decoded arbiter addresses
    /// @return remaining Remaining calldata after all arbiters
    function decodeArbiterConfig(bytes calldata initData)
        internal
        pure
        returns (address[] memory arbiters, bytes calldata remaining)
    {
        // Read count of arbiters
        uint256 count = uint256(bytes32(initData[0:32]));
        arbiters = new address[](count);

        // Read each arbiter address
        for (uint256 i = 0; i < count; i++) {
            uint256 offset = 32 + i * 20;
            arbiters[i] = address(bytes20(initData[offset:offset + 20]));
        }

        // Calculate remaining data
        remaining = initData[32 + count * 20:];
    }

    /*//////////////////////////////////////////////////////////////
                       EXPIRY CONFIG DECODING
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

    /// @notice Decodes expiry bounds (min/max) from initialization data
    /// @dev Returns packed format for efficient storage
    /// @param initData Calldata starting with expiry config
    /// @return packed Packed expiry value (lower 128 bits = min, upper 128 bits = max)
    /// @return remaining Remaining calldata after expiry config (initData[32:])
    function decodeExpiryConfig(bytes calldata initData)
        internal
        pure
        returns (uint256 packed, bytes calldata remaining)
    {
        // Read min and max expiry values
        uint128 minExpiry = uint128(bytes16(initData[0:16]));
        uint128 maxExpiry = uint128(bytes16(initData[16:32]));
        // Pack into single uint256
        packed = packUint128(minExpiry, maxExpiry);
        // Calculate remaining data
        remaining = initData[32:];
    }

    /*//////////////////////////////////////////////////////////////
                     RECIPIENT CONFIG DECODING
    //////////////////////////////////////////////////////////////

    Layout: [count: 32 bytes][entries...]
    Entry:  [targetChainId: 32 bytes][recipient: 20 bytes] = 52 bytes each

    ┌────────────────────────────────────────────────────────┐
    │  Recipient Config                                      │
    │  ┌────────────────────────────────────────────────┐    │
    │  │  count (uint256) - 32 bytes                    │    │
    │  └────────────────────────────────────────────────┘    │
    │  ┌────────────────────────────────────────────────┐    │
    │  │  Entry 0 (52 bytes):                           │    │
    │  │  ┌────────────────────┬────────────────────┐   │    │
    │  │  │ targetChainId (32) │ recipient (20)     │   │    │
    │  │  └────────────────────┴────────────────────┘   │    │
    │  └────────────────────────────────────────────────┘    │
    │  ... repeat for count entries ...                      │
    └────────────────────────────────────────────────────────┘

    Total size: 32 + (count * 52) bytes

    //////////////////////////////////////////////////////////////*/

    /// @notice Decodes recipient configurations from initialization data
    /// @dev Each entry maps a target chain ID to a required recipient address
    /// @param initData Calldata starting with recipient config
    /// @return configs Array of RecipientStorageConfig structs
    /// @return remaining Remaining calldata after all recipient configs
    function decodeRecipientConfig(bytes calldata initData)
        internal
        pure
        returns (RecipientStorageConfig[] memory configs, bytes calldata remaining)
    {
        // Read count of recipient entries
        uint256 count = uint256(bytes32(initData[0:32]));
        configs = new RecipientStorageConfig[](count);

        // Read each recipient entry
        for (uint256 i = 0; i < count; i++) {
            uint256 offset = 32 + i * 52;
            uint256 chainId = uint256(bytes32(initData[offset:offset + 32]));
            address recipient = address(bytes20(initData[offset + 32:offset + 52]));
            // Store in configs array
            configs[i] = RecipientStorageConfig(chainId, recipient);
        }

        // Calculate remaining data
        remaining = initData[32 + count * 52:];
    }

    /*//////////////////////////////////////////////////////////////
                    FILL EXPIRY CONFIG DECODING
    //////////////////////////////////////////////////////////////

    Layout: [count: 32 bytes][entries...]
    Entry:  [targetChainId: 32][minFillExpiry: 16][maxFillExpiry: 16] = 64 bytes each

    ┌────────────────────────────────────────────────────────┐
    │  FillExpiry Config                                     │
    │  ┌────────────────────────────────────────────────┐    │
    │  │  count (uint256) - 32 bytes                    │    │
    │  └────────────────────────────────────────────────┘    │
    │  ┌────────────────────────────────────────────────┐    │
    │  │  Entry (64 bytes):                             │    │
    │  │  ┌─────────────┬─────────────┬─────────────┐   │    │
    │  │  │ chainId(32) │ min(16)     │ max(16)     │   │    │
    │  │  └─────────────┴─────────────┴─────────────┘   │    │
    │  └────────────────────────────────────────────────┘    │
    │  ... repeat for count entries ...                      │
    └────────────────────────────────────────────────────────┘

    Total size: 32 + (count * 64) bytes

    //////////////////////////////////////////////////////////////*/

    /// @notice Decodes fill expiry configurations from initialization data
    /// @dev Each entry maps a target chain ID to min/max fill expiry bounds
    /// @param initData Calldata starting with fill expiry config
    /// @return configs Array of FillExpiryStorageConfig structs
    /// @return remaining Remaining calldata after all fill expiry configs
    function decodeFillExpiryConfig(bytes calldata initData)
        internal
        pure
        returns (FillExpiryStorageConfig[] memory configs, bytes calldata remaining)
    {
        // Read count of fill expiry entries
        uint256 count = uint256(bytes32(initData[0:32]));
        configs = new FillExpiryStorageConfig[](count);

        // Read each fill expiry entry
        for (uint256 i = 0; i < count; i++) {
            uint256 offset = 32 + i * 64;
            uint256 chainId = uint256(bytes32(initData[offset:offset + 32]));
            uint128 minFillExpiry = uint128(bytes16(initData[offset + 32:offset + 48]));
            uint128 maxFillExpiry = uint128(bytes16(initData[offset + 48:offset + 64]));

            // Store in configs array
            configs[i] = FillExpiryStorageConfig(chainId, minFillExpiry, maxFillExpiry);
        }

        // Calculate remaining data
        remaining = initData[32 + count * 64:];
    }

    /*//////////////////////////////////////////////////////////////
                     TOKEN OUT CONFIG DECODING
    //////////////////////////////////////////////////////////////

    Layout: [count: 32 bytes][entries...]
    Entry:  [targetChainId: 32 bytes][token: 20 bytes] = 52 bytes each

    ┌────────────────────────────────────────────────────────┐
    │  TokenOut Config                                       │
    │  ┌────────────────────────────────────────────────┐    │
    │  │  count (uint256) - 32 bytes                    │    │
    │  └────────────────────────────────────────────────┘    │
    │  ┌────────────────────────────────────────────────┐    │
    │  │  Entry (52 bytes):                             │    │
    │  │  ┌────────────────────┬────────────────────┐   │    │
    │  │  │ targetChainId (32) │ token (20)         │   │    │
    │  │  └────────────────────┴────────────────────┘   │    │
    │  └────────────────────────────────────────────────┘    │
    │  ... repeat for count entries ...                      │
    └────────────────────────────────────────────────────────┘

    Total size: 32 + (count * 52) bytes

    //////////////////////////////////////////////////////////////*/

    /// @notice Decodes token out configurations from initialization data
    /// @dev Each entry adds a token to the whitelist for a target chain
    /// @param initData Calldata starting with token out config
    /// @return configs Array of TokenOutStorageConfig structs
    /// @return remaining Remaining calldata after all token out configs
    function decodeTokenOutConfig(bytes calldata initData)
        internal
        pure
        returns (TokenOutStorageConfig[] memory configs, bytes calldata remaining)
    {
        // Read count of token out entries
        uint256 count = uint256(bytes32(initData[0:32]));
        configs = new TokenOutStorageConfig[](count);

        // Read each token out entry
        for (uint256 i = 0; i < count; i++) {
            uint256 offset = 32 + i * 52;
            uint256 chainId = uint256(bytes32(initData[offset:offset + 32]));
            address token = address(bytes20(initData[offset + 32:offset + 52]));

            // Store in configs array
            configs[i] = TokenOutStorageConfig(chainId, token);
        }

        // Calculate remaining data
        remaining = initData[32 + count * 52:];
    }

    /*//////////////////////////////////////////////////////////////
                       ORIGIN OPS CONFIG DECODING
    //////////////////////////////////////////////////////////////

    Layout: [count: 32 bytes][entries...]
    Entry:  [chainId: 32 bytes][requireOriginOps: 1 byte] = 33 bytes each

    ┌────────────────────────────────────────────────────────┐
    │  OriginOps Config                                      │
    │  ┌────────────────────────────────────────────────┐    │
    │  │  count (uint256) - 32 bytes                    │    │
    │  └────────────────────────────────────────────────┘    │
    │  ┌────────────────────────────────────────────────┐    │
    │  │  Entry (33 bytes):                             │    │
    │  │  ┌────────────────────┬─────────────────────┐  │    │
    │  │  │ chainId (32)       │ required (1)        │  │    │
    │  │  └────────────────────┴─────────────────────┘  │    │
    │  └────────────────────────────────────────────────┘    │
    │  ... repeat for count entries ...                      │
    └────────────────────────────────────────────────────────┘

    Total size: 32 + (count * 33) bytes

    //////////////////////////////////////////////////////////////*/

    /// @notice Decodes origin operations requirement configurations
    /// @dev Each entry specifies whether originOps must be present for a chain
    /// @param initData Calldata starting with origin ops config
    /// @return configs Array of OriginOpsStorageConfig structs
    /// @return remaining Remaining calldata after all origin ops configs
    function decodeOriginOpsConfig(bytes calldata initData)
        internal
        pure
        returns (OriginOpsStorageConfig[] memory configs, bytes calldata remaining)
    {
        // Read count of origin ops entries
        uint256 count = uint256(bytes32(initData[0:32]));
        configs = new OriginOpsStorageConfig[](count);

        // Read each origin ops entry
        for (uint256 i = 0; i < count; i++) {
            uint256 offset = 32 + i * 33;
            uint256 chainId = uint256(bytes32(initData[offset:offset + 32]));
            bool requireOriginOps = uint8(initData[offset + 32]) != 0;

            // Store in configs array
            configs[i] = OriginOpsStorageConfig(chainId, requireOriginOps);
        }

        // Calculate remaining data
        remaining = initData[32 + count * 33:];
    }

    /*//////////////////////////////////////////////////////////////
                       DEST OPS CONFIG DECODING
    //////////////////////////////////////////////////////////////

    Layout: [count: 32 bytes][entries...]
    Entry:  [targetChainId: 32 bytes][requireDestOps: 1 byte] = 33 bytes each

    ┌────────────────────────────────────────────────────────┐
    │  DestOps Config                                        │
    │  ┌────────────────────────────────────────────────┐    │
    │  │  count (uint256) - 32 bytes                    │    │
    │  └────────────────────────────────────────────────┘    │
    │  ┌────────────────────────────────────────────────┐    │
    │  │  Entry (33 bytes):                             │    │
    │  │  ┌────────────────────┬─────────────────────┐  │    │
    │  │  │ targetChainId (32) │ required (1)        │  │    │
    │  │  └────────────────────┴─────────────────────┘  │    │
    │  └────────────────────────────────────────────────┘    │
    │  ... repeat for count entries ...                      │
    └────────────────────────────────────────────────────────┘

    Total size: 32 + (count * 33) bytes

    //////////////////////////////////////////////////////////////*/

    /// @notice Decodes destination operations requirement configurations
    /// @dev Each entry specifies whether destOps must be present for a target chain
    /// @param initData Calldata starting with dest ops config
    /// @return configs Array of DestOpsStorageConfig structs
    /// @return remaining Remaining calldata after all dest ops configs
    function decodeDestOpsConfig(bytes calldata initData)
        internal
        pure
        returns (DestOpsStorageConfig[] memory configs, bytes calldata remaining)
    {
        // Read count of dest ops entries
        uint256 count = uint256(bytes32(initData[0:32]));
        configs = new DestOpsStorageConfig[](count);

        // Read each dest ops entry
        for (uint256 i = 0; i < count; i++) {
            uint256 offset = 32 + i * 33;
            uint256 chainId = uint256(bytes32(initData[offset:offset + 32]));
            bool requireDestOps = uint8(initData[offset + 32]) != 0;

            // Store in configs array
            configs[i] = DestOpsStorageConfig(chainId, requireDestOps);
        }

        // Calculate remaining data
        remaining = initData[32 + count * 33:];
    }

    /*//////////////////////////////////////////////////////////////
                      QUALIFICATION CONFIG DECODING
    //////////////////////////////////////////////////////////////

    Layout: [count: 32 bytes][entries...]
    Entry (variable size):
      [chainId: 32][arbiter: 20][rootNodeIndex: 1]
      [ruleCount: 32][rules...][packedNodesCount: 32][packedNodes...]

    Rule (42 bytes each):
      [condition: 1][offset: 8][length: 1][ref: 32]

    PackedNode (32 bytes each):
      [node: 32]

    ┌────────────────────────────────────────────────────────┐
    │  Qualification Config                                  │
    │  ┌────────────────────────────────────────────────┐    │
    │  │  count (uint256) - 32 bytes                    │    │
    │  └────────────────────────────────────────────────┘    │
    │  ┌────────────────────────────────────────────────┐    │
    │  │  Entry (variable):                             │    │
    │  │  ┌─────────────────────────────────────────┐   │    │
    │  │  │ chainId (32) | arbiter (20) | root (1)  │   │    │
    │  │  ├─────────────────────────────────────────┤   │    │
    │  │  │ ruleCount (32)                          │   │    │
    │  │  │ Rule: [cond(1)|off(8)|len(1)|ref(32)]   │   │    │
    │  │  │ ... more rules ...                      │   │    │
    │  │  ├─────────────────────────────────────────┤   │    │
    │  │  │ packedNodesCount (32)                   │   │    │
    │  │  │ PackedNode: [node (32)]                 │   │    │
    │  │  │ ... more nodes ...                      │   │    │
    │  │  └─────────────────────────────────────────┘   │    │
    │  └────────────────────────────────────────────────┘    │
    └────────────────────────────────────────────────────────┘

    //////////////////////////////////////////////////////////////*/

    /// @notice Decodes qualification configurations with parameter rules
    /// @dev Each entry contains an expression tree for validating qualification data.
    ///      Rules are evaluated using the ArgPolicyTreeLibV2 expression evaluator.
    /// @param initData Calldata starting with qualification config
    /// @return configs Array of QualificationStorageConfig structs
    /// @return remaining Remaining calldata after all qualification configs
    function decodeQualificationConfig(bytes calldata initData)
        internal
        pure
        returns (QualificationStorageConfig[] memory configs, bytes calldata remaining)
    {
        // Read count of qualification entries
        uint256 count = uint256(bytes32(initData[0:32]));
        configs = new QualificationStorageConfig[](count);
        uint256 offset = 32;

        // Read each qualification entry
        for (uint256 j = 0; j < count; j++) {
            // Decode chainId (32 bytes)
            uint256 chainId = uint256(bytes32(initData[offset:offset + 32]));
            offset += 32;

            // Decode arbiter address (20 bytes)
            address arbiter = address(bytes20(initData[offset:offset + 20]));
            offset += 20;

            // Decode root node index (1 byte)
            uint8 rootNodeIndex = uint8(initData[offset]);
            offset += 1;

            // Decode rule count (32 bytes)
            uint256 ruleCount = uint256(bytes32(initData[offset:offset + 32]));
            offset += 32;

            // Decode each rule (42 bytes each)
            ParamRule[] memory paramRules = new ParamRule[](ruleCount);
            for (uint256 i = 0; i < ruleCount; i++) {
                paramRules[i] = ParamRule({
                    condition: ParamCondition(uint8(initData[offset])),
                    offset: uint64(bytes8(initData[offset + 1:offset + 9])),
                    length: uint8(initData[offset + 9]),
                    ref: bytes32(initData[offset + 10:offset + 42])
                });
                offset += 42;
            }

            // Decode packed nodes count (32 bytes)
            uint256 packedNodesLength = uint256(bytes32(initData[offset:offset + 32]));
            offset += 32;

            // Decode each packed node (32 bytes each)
            uint256[] memory packedNodes = new uint256[](packedNodesLength);
            for (uint256 i = 0; i < packedNodesLength; i++) {
                packedNodes[i] = uint256(bytes32(initData[offset:offset + 32]));
                offset += 32;
            }

            // Assemble the ParamRules struct
            ParamRules memory rules = ParamRules({
                rootNodeIndex: rootNodeIndex, rules: paramRules, packedNodes: packedNodes
            });

            configs[j] = QualificationStorageConfig(chainId, arbiter, rules);
        }

        remaining = initData[offset:];
    }

    /*//////////////////////////////////////////////////////////////
                       SUB-POLICY CONFIG DECODING
    //////////////////////////////////////////////////////////////

    Layout: [count: 32 bytes][entries...]
    Entry (variable size):
      [fieldId: 1][policyAddress: 20][initDataLength: 32][initData: variable]

    ┌────────────────────────────────────────────────────────┐
    │  SubPolicy Config                                      │
    │  ┌────────────────────────────────────────────────┐    │
    │  │  count (uint256) - 32 bytes                    │    │
    │  └────────────────────────────────────────────────┘    │
    │  ┌────────────────────────────────────────────────┐    │
    │  │  Entry (variable):                             │    │
    │  │  ┌─────────────────────────────────────────┐   │    │
    │  │  │ fieldId (1) | policyAddress (20)        │   │    │
    │  │  ├─────────────────────────────────────────┤   │    │
    │  │  │ initDataLength (32)                     │   │    │
    │  │  ├─────────────────────────────────────────┤   │    │
    │  │  │ initData (initDataLength bytes)         │   │    │
    │  │  └─────────────────────────────────────────┘   │    │
    │  └────────────────────────────────────────────────┘    │
    │  ... repeat for count entries ...                      │
    └────────────────────────────────────────────────────────┘

    //////////////////////////////////////////////////////////////*/

    /// @notice Decodes sub-policy configurations
    /// @dev Sub-policies are external I1271Policy contracts that handle
    ///      validation for specific fields when mode is MODE_CHECK_SUBPOLICY
    /// @param initData Calldata starting with sub-policy config
    /// @return configs Array of SubPolicyConfig structs
    /// @return remaining Remaining calldata after all sub-policy configs
    function decodeSubPolicyConfig(bytes calldata initData)
        internal
        pure
        returns (SubPolicyConfig[] memory configs, bytes calldata remaining)
    {
        // Read count of sub-policy entries
        uint256 count = uint256(bytes32(initData[0:32]));
        configs = new SubPolicyConfig[](count);
        uint256 offset = 32;

        // Read each sub-policy entry
        for (uint256 i = 0; i < count; i++) {
            // Decode fieldId (1 byte)
            uint8 fieldId = uint8(initData[offset]);
            offset += 1;

            // Decode policy address (20 bytes)
            address policyAddress = address(bytes20(initData[offset:offset + 20]));
            offset += 20;

            // Decode init data length (32 bytes)
            uint256 initDataLength = uint256(bytes32(initData[offset:offset + 32]));
            offset += 32;

            // Decode init data (variable length)
            bytes memory policyInitData = initData[offset:offset + initDataLength];
            offset += initDataLength;

            configs[i] = SubPolicyConfig({
                fieldId: fieldId, policyAddress: policyAddress, initData: policyInitData
            });
        }

        // Calculate remaining data
        remaining = initData[offset:];
    }
}
