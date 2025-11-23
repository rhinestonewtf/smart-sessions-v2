// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Libraries
import { Permit2StorageLib } from "@policies/claimv2/permit2/lib/StorageLib.sol";

// Types
import { ParamRules, ParamRule } from "@policies/claimv2/compact/types/DataTypes.sol";
import { ParamCondition } from "@smartsessions/external/policies/ArgPolicy/ArgPolicy.sol";
import {
    SubPolicyConfig,
    TokenInStorageConfig,
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
    FIELD_DEADLINE,
    FIELD_TOKEN_IN,
    FIELD_RECIPIENT,
    FIELD_FILL_EXPIRY,
    FIELD_TOKEN_OUT,
    FIELD_ORIGIN_OPS,
    FIELD_DEST_OPS,
    FIELD_QUALIFICATION
} from "@policies/claimv2/permit2/types/DataTypes.sol";

/* //////////////////////////////////////////////////////////////
                            TYPES
//////////////////////////////////////////////////////////////*/

type PolicyConfig is uint32; // Mode configuration: 2 bits per field

using { neQConfig as != } for PolicyConfig global;
using { eqConfig as == } for PolicyConfig global;

/// @notice Checks if the current config does not match the given config
function neQConfig(PolicyConfig self, PolicyConfig config) pure returns (bool) {
    return PolicyConfig.unwrap(self) != PolicyConfig.unwrap(config);
}

/// @notice Checks if the current config matches the given config
function eqConfig(PolicyConfig self, PolicyConfig config) pure returns (bool) {
    return PolicyConfig.unwrap(self) == PolicyConfig.unwrap(config);
}

/// @title Config Library
/// @notice Library for managing condition configurations in the Permit2ClaimPolicy
library Permit2ConfigLib {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using Permit2StorageLib for *;
    using Permit2ConfigLib for *;

    /* //////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    struct InitData {
        // Mode configuration (2 bits per field, 9 fields)
        uint32 modeConfig;
        // Storage-based configs
        address arbiter;
        uint128 minDeadline;
        uint128 maxDeadline;
        TokenInStorageConfig[] tokenInConfigs;
        RecipientStorageConfig[] recipientConfigs;
        FillExpiryStorageConfig[] fillExpiryConfigs;
        TokenOutStorageConfig[] tokenOutConfigs;
        OriginOpsStorageConfig[] originOpsConfigs;
        DestOpsStorageConfig[] destOpsConfigs;
        QualificationStorageConfig[] qualificationConfigs;
        // Sub-policy configs
        SubPolicyConfig[] subPolicies;
    }

    /* //////////////////////////////////////////////////////////////
                            MODE EXTRACTION
    //////////////////////////////////////////////////////////////*/

    /// @notice Gets the mode for a specific field
    /// @param config The policy configuration
    /// @param fieldId The field ID (0-8)
    /// @return mode The 2-bit mode (0-3)
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

    /// @notice Checks if arbiter validation is enabled (mode != SKIP)
    function hasCheckArbiter(PolicyConfig config) internal pure returns (bool) {
        return getFieldMode(config, FIELD_ARBITER) != MODE_SKIP;
    }

    /// @notice Checks if deadline validation is enabled (mode != SKIP)
    function hasCheckDeadline(PolicyConfig config) internal pure returns (bool) {
        return getFieldMode(config, FIELD_DEADLINE) != MODE_SKIP;
    }

    /// @notice Checks if tokenIn validation is enabled (mode != SKIP)
    function hasCheckTokenIn(PolicyConfig config) internal pure returns (bool) {
        return getFieldMode(config, FIELD_TOKEN_IN) != MODE_SKIP;
    }

    /// @notice Checks if recipient validation is enabled (mode != SKIP)
    function hasCheckRecipient(PolicyConfig config) internal pure returns (bool) {
        return getFieldMode(config, FIELD_RECIPIENT) != MODE_SKIP;
    }

    /// @notice Checks if fillExpiry validation is enabled (mode != SKIP)
    function hasCheckFillExpiry(PolicyConfig config) internal pure returns (bool) {
        return getFieldMode(config, FIELD_FILL_EXPIRY) != MODE_SKIP;
    }

    /// @notice Checks if tokenOut validation is enabled (mode != SKIP)
    function hasCheckTokenOut(PolicyConfig config) internal pure returns (bool) {
        return getFieldMode(config, FIELD_TOKEN_OUT) != MODE_SKIP;
    }

    /// @notice Checks if originOps validation is enabled (mode != SKIP)
    function hasCheckOriginOps(PolicyConfig config) internal pure returns (bool) {
        return getFieldMode(config, FIELD_ORIGIN_OPS) != MODE_SKIP;
    }

    /// @notice Checks if destOps validation is enabled (mode != SKIP)
    function hasCheckDestOps(PolicyConfig config) internal pure returns (bool) {
        return getFieldMode(config, FIELD_DEST_OPS) != MODE_SKIP;
    }

    /// @notice Checks if qualification validation is enabled (mode != SKIP)
    function hasCheckQualification(PolicyConfig config) internal pure returns (bool) {
        return getFieldMode(config, FIELD_QUALIFICATION) != MODE_SKIP;
    }

    /* //////////////////////////////////////////////////////////////
                                 DECODE
    //////////////////////////////////////////////////////////////*/

    /// @notice Decodes initialization data based on mode configuration
    /// @param modeConfig The mode configuration (2 bits per field)
    /// @param initData The initialization data to decode
    /// @return init The decoded InitData struct
    function decodeInitData(
        uint32 modeConfig,
        bytes calldata initData
    )
        internal
        pure
        returns (InitData memory init)
    {
        init.modeConfig = modeConfig;
        bytes calldata data = initData;

        // Decode fields based on mode

        // Arbiter
        if (modeConfig.getFieldMode(FIELD_ARBITER).isStorageMode()) {
            (init.arbiter, data) = decodeArbiterConfig(data);
        }

        // Deadline
        if (modeConfig.getFieldMode(FIELD_DEADLINE).isStorageMode()) {
            uint256 packed;
            (packed, data) = decodeDeadlineConfig(data);
            (init.minDeadline, init.maxDeadline) = unpackUint128(packed);
        }

        // Token In
        if (modeConfig.getFieldMode(FIELD_TOKEN_IN).isStorageMode()) {
            (init.tokenInConfigs, data) = decodeTokenInConfig(data);
        }

        // Recipient
        if (modeConfig.getFieldMode(FIELD_RECIPIENT).isStorageMode()) {
            (init.recipientConfigs, data) = decodeRecipientConfig(data);
        }

        // Fill Expiry
        if (modeConfig.getFieldMode(FIELD_FILL_EXPIRY).isStorageMode()) {
            (init.fillExpiryConfigs, data) = decodeFillExpiryConfig(data);
        }

        // Token Out
        if (modeConfig.getFieldMode(FIELD_TOKEN_OUT).isStorageMode()) {
            (init.tokenOutConfigs, data) = decodeTokenOutConfig(data);
        }

        // Origin Ops
        if (modeConfig.getFieldMode(FIELD_ORIGIN_OPS).isStorageMode()) {
            (init.originOpsConfigs, data) = decodeOriginOpsConfig(data);
        }

        // Dest Ops
        if (modeConfig.getFieldMode(FIELD_DEST_OPS).isStorageMode()) {
            (init.destOpsConfigs, data) = decodeDestOpsConfig(data);
        }

        // Qualification
        if (modeConfig.getFieldMode(FIELD_QUALIFICATION).isStorageMode()) {
            (init.qualificationConfigs, data) = decodeQualificationConfig(data);
        }

        // Decode sub-policies if any remaining data
        if (data.length > 0) {
            (init.subPolicies, data) = decodeSubPolicyConfig(data);
        }
    }

    /// @notice Decodes the arbiter address from the initialization data
    /// @param initData The initialization data containing the arbiter address
    /// @return arbiter The arbiter address
    /// @return data The remaining initialization data after decoding
    function decodeArbiterConfig(bytes calldata initData)
        internal
        pure
        returns (address arbiter, bytes calldata data)
    {
        arbiter = address(bytes20(initData[0:20]));
        data = initData[20:];
    }

    /// @notice Decodes the deadline bounds from the initialization data
    /// @param initData The initialization data containing min/max deadline
    /// @return packedDeadline Packed deadline (uint128 min | uint128 max)
    /// @return data The remaining initialization data after decoding
    function decodeDeadlineConfig(bytes calldata initData)
        internal
        pure
        returns (uint256 packedDeadline, bytes calldata data)
    {
        uint128 minDeadline = uint128(bytes16(initData[0:16]));
        uint128 maxDeadline = uint128(bytes16(initData[16:32]));
        packedDeadline = packUint128(minDeadline, maxDeadline);
        data = initData[32:];
    }

    /// @notice Decodes sub-policy configurations from the initialization data
    /// @dev Format: count (32) + [fieldId (1) + policyAddress (20) + initDataLength (32) +
    /// initData] * count
    /// @param initData The initialization data containing sub-policy configs
    /// @return configs Array of sub-policy configurations
    /// @return data The remaining initialization data after decoding
    function decodeSubPolicyConfig(bytes calldata initData)
        internal
        pure
        returns (SubPolicyConfig[] memory configs, bytes calldata data)
    {
        uint256 count = uint256(bytes32(initData[0:32]));
        configs = new SubPolicyConfig[](count);
        uint256 offset = 32;

        for (uint256 i = 0; i < count; i++) {
            // Decode fieldId (1 byte)
            uint8 fieldId = uint8(initData[offset]);
            offset += 1;

            // Decode policy address (20 bytes)
            address policyAddress = address(bytes20(initData[offset:offset + 20]));
            offset += 20;

            // Decode init data length
            uint256 initDataLength = uint256(bytes32(initData[offset:offset + 32]));
            offset += 32;

            // Decode init data
            bytes memory policyInitData = initData[offset:offset + initDataLength];
            offset += initDataLength;

            configs[i] = SubPolicyConfig({
                fieldId: fieldId, policyAddress: policyAddress, initData: policyInitData
            });
        }

        data = initData[offset:];
    }

    /// @notice Decodes the tokenIn configuration from the initialization data
    /// @dev Each TokenInConfig: 32 (chainId) + 20 (token) = 52 bytes
    /// @param initData The initialization data containing tokenIn configs
    /// @return configs Array of TokenInStorageConfig structs
    /// @return data The remaining initialization data after decoding
    function decodeTokenInConfig(bytes calldata initData)
        internal
        pure
        returns (TokenInStorageConfig[] memory configs, bytes calldata data)
    {
        uint256 count = uint256(bytes32(initData[0:32]));
        configs = new TokenInStorageConfig[](count);

        for (uint256 i = 0; i < count; i++) {
            uint256 offset = 32 + i * 52;
            uint256 chainId = uint256(bytes32(initData[offset:offset + 32]));
            address token = address(bytes20(initData[offset + 32:offset + 52]));

            configs[i] = TokenInStorageConfig(chainId, token);
        }

        data = initData[32 + count * 52:];
    }

    /// @notice Decodes the recipient configuration from the initialization data
    /// @dev Each RecipientConfig: 32 (targetChainId) + 20 (recipient) = 52 bytes
    /// @param initData The initialization data containing recipient configs
    /// @return configs Array of RecipientStorageConfig structs
    /// @return data The remaining initialization data after decoding
    function decodeRecipientConfig(bytes calldata initData)
        internal
        pure
        returns (RecipientStorageConfig[] memory configs, bytes calldata data)
    {
        uint256 count = uint256(bytes32(initData[0:32]));
        configs = new RecipientStorageConfig[](count);

        for (uint256 i = 0; i < count; i++) {
            uint256 offset = 32 + i * 52;
            uint256 chainId = uint256(bytes32(initData[offset:offset + 32]));
            address recipient = address(bytes20(initData[offset + 32:offset + 52]));

            configs[i] = RecipientStorageConfig(chainId, recipient);
        }

        data = initData[32 + count * 52:];
    }

    /// @notice Decodes the fillExpiry configuration from the initialization data
    /// @dev Each FillExpiryConfig: 32 (targetChainId) + 16 (minFillExpiry) + 16 (maxFillExpiry) =
    /// 64 bytes
    /// @param initData The initialization data containing fillExpiry configs
    /// @return configs Array of FillExpiryStorageConfig structs
    /// @return data The remaining initialization data after decoding
    function decodeFillExpiryConfig(bytes calldata initData)
        internal
        pure
        returns (FillExpiryStorageConfig[] memory configs, bytes calldata data)
    {
        uint256 count = uint256(bytes32(initData[0:32]));
        configs = new FillExpiryStorageConfig[](count);

        for (uint256 i = 0; i < count; i++) {
            uint256 offset = 32 + i * 64;
            uint256 chainId = uint256(bytes32(initData[offset:offset + 32]));
            uint128 minFillExpiry = uint128(bytes16(initData[offset + 32:offset + 48]));
            uint128 maxFillExpiry = uint128(bytes16(initData[offset + 48:offset + 64]));

            configs[i] = FillExpiryStorageConfig(chainId, minFillExpiry, maxFillExpiry);
        }

        data = initData[32 + count * 64:];
    }

    /// @notice Decodes the tokenOut configuration from the initialization data
    /// @dev Each TokenOutConfig: 32 (targetChainId) + 20 (token) = 52 bytes
    /// @param initData The initialization data containing tokenOut configs
    /// @return configs Array of TokenOutStorageConfig structs
    /// @return data The remaining initialization data after decoding
    function decodeTokenOutConfig(bytes calldata initData)
        internal
        pure
        returns (TokenOutStorageConfig[] memory configs, bytes calldata data)
    {
        uint256 count = uint256(bytes32(initData[0:32]));
        configs = new TokenOutStorageConfig[](count);

        for (uint256 i = 0; i < count; i++) {
            uint256 offset = 32 + i * 52;
            uint256 chainId = uint256(bytes32(initData[offset:offset + 32]));
            address token = address(bytes20(initData[offset + 32:offset + 52]));

            configs[i] = TokenOutStorageConfig(chainId, token);
        }

        data = initData[32 + count * 52:];
    }

    /// @notice Decodes the origin ops requirement configuration from the initialization data
    /// @dev Each OriginOpsConfig: 32 (chainId) + 1 (requireOriginOps) = 33 bytes
    /// @param initData The initialization data containing origin ops requirement configs
    /// @return configs Array of OriginOpsStorageConfig structs
    /// @return data The remaining initialization data after decoding
    function decodeOriginOpsConfig(bytes calldata initData)
        internal
        pure
        returns (OriginOpsStorageConfig[] memory configs, bytes calldata data)
    {
        uint256 count = uint256(bytes32(initData[0:32]));
        configs = new OriginOpsStorageConfig[](count);

        for (uint256 i = 0; i < count; i++) {
            uint256 offset = 32 + i * 33;
            uint256 chainId = uint256(bytes32(initData[offset:offset + 32]));
            bool requireOriginOps = uint8(initData[offset + 32]) != 0;

            configs[i] = OriginOpsStorageConfig(chainId, requireOriginOps);
        }

        data = initData[32 + count * 33:];
    }

    /// @notice Decodes the dest ops requirement configuration from the initialization data
    /// @dev Each DestOpsConfig: 32 (targetChainId) + 1 (requireDestOps) = 33 bytes
    /// @param initData The initialization data containing dest ops requirement configs
    /// @return configs Array of DestOpsStorageConfig structs
    /// @return data The remaining initialization data after decoding
    function decodeDestOpsConfig(bytes calldata initData)
        internal
        pure
        returns (DestOpsStorageConfig[] memory configs, bytes calldata data)
    {
        uint256 count = uint256(bytes32(initData[0:32]));
        configs = new DestOpsStorageConfig[](count);

        for (uint256 i = 0; i < count; i++) {
            uint256 offset = 32 + i * 33;
            uint256 chainId = uint256(bytes32(initData[offset:offset + 32]));
            bool requireDestOps = uint8(initData[offset + 32]) != 0;

            configs[i] = DestOpsStorageConfig(chainId, requireDestOps);
        }

        data = initData[32 + count * 33:];
    }

    /// @notice Decodes the qualification configuration from the initialization data
    /// @dev Format: count (32) + [chainId (32) + arbiter (20) + rootNodeIndex (1) + ruleCount (32)
    /// + rules + packedNodesLength (32) + packedNodes] * count
    /// @param initData The initialization data containing qualification configs
    /// @return configs Array of QualificationStorageConfig structs
    /// @return data The remaining initialization data after decoding
    function decodeQualificationConfig(bytes calldata initData)
        internal
        pure
        returns (QualificationStorageConfig[] memory configs, bytes calldata data)
    {
        uint256 count = uint256(bytes32(initData[0:32]));
        configs = new QualificationStorageConfig[](count);
        uint256 offset = 32;

        for (uint256 j = 0; j < count; j++) {
            // Decode chainId
            uint256 chainId = uint256(bytes32(initData[offset:offset + 32]));
            offset += 32;

            // Decode qualification arbiter
            address arbiter = address(bytes20(initData[offset:offset + 20]));
            offset += 20;

            // Decode the root node index
            uint8 rootNodeIndex = uint8(initData[offset]);
            offset += 1;

            // Decode the number of rules
            uint256 ruleCount = uint256(bytes32(initData[offset:offset + 32]));
            offset += 32;

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

            // Decode packed nodes length
            uint256 packedNodesLength = uint256(bytes32(initData[offset:offset + 32]));
            offset += 32;

            uint256[] memory packedNodes = new uint256[](packedNodesLength);
            for (uint256 i = 0; i < packedNodesLength; i++) {
                packedNodes[i] = uint256(bytes32(initData[offset:offset + 32]));
                offset += 32;
            }

            ParamRules memory rules = ParamRules({
                rootNodeIndex: rootNodeIndex, rules: paramRules, packedNodes: packedNodes
            });

            configs[j] = QualificationStorageConfig(chainId, arbiter, rules);
        }

        data = initData[offset:];
    }

    /* //////////////////////////////////////////////////////////////
                          PACK/UNPACK HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Packs two uint128 values into a single uint256
    /// @param lower Lower 128 bits value (min)
    /// @param upper Upper 128 bits value (max)
    /// @return packed The packed uint256 value
    function packUint128(uint128 lower, uint128 upper) internal pure returns (uint256 packed) {
        packed = uint256(lower) | (uint256(upper) << 128);
    }

    /// @notice Unpacks a uint256 into two uint128 values
    /// @param packed The packed uint256 value
    /// @return lower Lower 128 bits value (min)
    /// @return upper Upper 128 bits value (max)
    function unpackUint128(uint256 packed) internal pure returns (uint128 lower, uint128 upper) {
        lower = uint128(packed);
        upper = uint128(packed >> 128);
    }

    /*//////////////////////////////////////////////////////////////
                            MODE EXTRACTION
    //////////////////////////////////////////////////////////////*/

    /// @notice Extracts the mode for a specific field from the packed mode config
    /// @param modeConfig The packed mode configuration (uint32)
    /// @param fieldId The field ID (0-8)
    /// @return mode The 2-bit mode value (0-3)
    function getFieldMode(
        uint32 modeConfig,
        uint8 fieldId
    )
        internal
        pure
        returns (uint8 mode)
    {
        mode = uint8((modeConfig >> (fieldId * 2)) & 0x3);
    }

    /// @notice Sets the mode for a specific field in the packed mode config
    /// @param modeConfig The current packed mode configuration
    /// @param fieldId The field ID (0-8)
    /// @param mode The 2-bit mode value (0-3)
    /// @return newConfig The updated mode configuration
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

    /// @notice Checks if the mode requires storage initialization
    /// @param mode The mode to check
    /// @return True if mode is MODE_CHECK_STORAGE or MODE_CHECK_CATCHALL
    function isStorageMode(uint8 mode) internal pure returns (bool) {
        return mode == MODE_CHECK_STORAGE || mode == MODE_CHECK_CATCHALL;
    }

    /// @notice Checks if the mode is sub-policy delegation
    function isSubPolicyMode(uint8 mode) internal pure returns (bool) {
        return mode == MODE_CHECK_SUBPOLICY;
    }

    /// @notice Checks if a field should be initialized with storage
    /// @param modeConfig The mode configuration
    /// @param fieldId The field ID to check
    /// @return True if the field mode requires storage initialization
    function isStorageBased(uint32 modeConfig, uint8 fieldId) internal pure returns (bool) {
        uint8 mode = getFieldMode(PolicyConfig.wrap(modeConfig), fieldId);
        return mode == MODE_CHECK_STORAGE || mode == MODE_CHECK_CATCHALL;
    }

    /*//////////////////////////////////////////////////////////////
                                CATCHALL
    //////////////////////////////////////////////////////////////*/

    /// @notice If mode is catch all returns chainId 0, else returns given chainId
    function getEffectiveChainId(uint8 mode, uint256 chainId) internal pure returns (uint256) {
        if (mode == MODE_CHECK_CATCHALL) {
            return 0;
        }
        return chainId;
    }
}
