// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Types
import { ParamCondition } from "@smartsessions/external/policies/ArgPolicy/ArgPolicy.sol";
import {
    SubPolicyConfig,
    ParamRules,
    ParamRule,
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
    FIELD_CLAIM_EXPIRES,
    FIELD_TOKEN_IN,
    FIELD_RECIPIENT,
    FIELD_FILL_EXPIRY,
    FIELD_TOKEN_OUT,
    FIELD_ORIGIN_OPS,
    FIELD_DEST_OPS,
    FIELD_QUALIFICATION
} from "@policies/compact/types/DataTypes.sol";

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
/// @notice Library for managing condition configurations in the MultiChainClaimPolicy
library ConfigLib {
    /* //////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    struct InitData {
        // Mode configuration (2 bits per field, 9 fields)
        uint32 modeConfig;
        // Storage-based configs
        address arbiter;
        uint128 minClaimExpires;
        uint128 maxClaimExpires;
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

    /// @notice Checks if claim expires validation is enabled (mode != SKIP)
    function hasCheckClaimExpires(PolicyConfig config) internal pure returns (bool) {
        return getFieldMode(config, FIELD_CLAIM_EXPIRES) != MODE_SKIP;
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

    /// @notice Decodes the claim expires bounds from the initialization data
    /// @param initData The initialization data containing min/max claim expires
    /// @return packedExpires Packed expiration (uint128 min | uint128 max)
    /// @return data The remaining initialization data after decoding
    function decodeClaimExpiresConfig(bytes calldata initData)
        internal
        pure
        returns (uint256 packedExpires, bytes calldata data)
    {
        uint128 minExpires = uint128(bytes16(initData[0:16]));
        uint128 maxExpires = uint128(bytes16(initData[16:32]));
        packedExpires = packUint128(minExpires, maxExpires);
        data = initData[32:];
    }

    /// @notice Decodes the tokenIn configuration from the initialization data
    /// @dev Each TokenInConfig: 32 (chainId) + 20 (token) + 12 (lockTag) = 64 bytes
    /// @param initData The initialization data containing tokenIn configs
    /// @return packedConfigs Array of packed tokenIn configurations
    /// @return chainIds Array of chainIds corresponding to configs
    /// @return data The remaining initialization data after decoding
    function decodeTokenInConfig(bytes calldata initData)
        internal
        pure
        returns (bytes32[] memory packedConfigs, uint256[] memory chainIds, bytes calldata data)
    {
        uint256 count = uint256(bytes32(initData[0:32]));
        packedConfigs = new bytes32[](count);
        chainIds = new uint256[](count);

        for (uint256 i = 0; i < count; i++) {
            uint256 offset = 32 + i * 64;
            chainIds[i] = uint256(bytes32(initData[offset:offset + 32]));
            address token = address(bytes20(initData[offset + 32:offset + 52]));
            bytes12 lockTag = bytes12(initData[offset + 52:offset + 64]);

            // Pack into bytes32: address (20 bytes) in lower bits, lockTag (12 bytes) in upper bits
            packedConfigs[i] = bytes32(uint256(uint160(token))) | (bytes32(lockTag) >> 160);
        }

        data = initData[32 + count * 64:];
    }

    /// @notice Decodes the recipient configuration from the initialization data
    /// @dev Each RecipientConfig: 32 (targetChainId) + 20 (recipient) = 52 bytes
    /// @param initData The initialization data containing recipient configs
    /// @return recipients Array of recipient addresses
    /// @return chainIds Array of targetChainIds corresponding to configs
    /// @return data The remaining initialization data after decoding
    function decodeRecipientConfig(bytes calldata initData)
        internal
        pure
        returns (address[] memory recipients, uint256[] memory chainIds, bytes calldata data)
    {
        uint256 count = uint256(bytes32(initData[0:32]));
        recipients = new address[](count);
        chainIds = new uint256[](count);

        for (uint256 i = 0; i < count; i++) {
            uint256 offset = 32 + i * 52;
            chainIds[i] = uint256(bytes32(initData[offset:offset + 32]));
            recipients[i] = address(bytes20(initData[offset + 32:offset + 52]));
        }

        data = initData[32 + count * 52:];
    }

    /// @notice Decodes the fillExpiry configuration from the initialization data
    /// @dev Each FillExpiryConfig: 32 (targetChainId) + 16 (minFillExpiry) + 16 (maxFillExpiry) =
    /// 64 bytes @param initData The initialization data containing fillExpiry configs
    /// @return packedExpiries Array of packed fill expiry values
    /// @return chainIds Array of targetChainIds corresponding to configs
    /// @return data The remaining initialization data after decoding
    function decodeFillExpiryConfig(bytes calldata initData)
        internal
        pure
        returns (uint256[] memory packedExpiries, uint256[] memory chainIds, bytes calldata data)
    {
        uint256 count = uint256(bytes32(initData[0:32]));
        packedExpiries = new uint256[](count);
        chainIds = new uint256[](count);

        for (uint256 i = 0; i < count; i++) {
            uint256 offset = 32 + i * 64;
            chainIds[i] = uint256(bytes32(initData[offset:offset + 32]));

            uint128 minFillExpiry = uint128(bytes16(initData[offset + 32:offset + 48]));
            uint128 maxFillExpiry = uint128(bytes16(initData[offset + 48:offset + 64]));

            packedExpiries[i] = packUint128(minFillExpiry, maxFillExpiry);
        }

        data = initData[32 + count * 64:];
    }

    /// @notice Decodes the tokenOut configuration from the initialization data
    /// @dev Each TokenOutConfig: 32 (targetChainId) + 20 (token) = 52 bytes
    /// @param initData The initialization data containing tokenOut configs
    /// @return tokens Array of token addresses
    /// @return chainIds Array of targetChainIds corresponding to configs
    /// @return data The remaining initialization data after decoding
    function decodeTokenOutConfig(bytes calldata initData)
        internal
        pure
        returns (address[] memory tokens, uint256[] memory chainIds, bytes calldata data)
    {
        uint256 count = uint256(bytes32(initData[0:32]));
        tokens = new address[](count);
        chainIds = new uint256[](count);

        for (uint256 i = 0; i < count; i++) {
            uint256 offset = 32 + i * 52;
            chainIds[i] = uint256(bytes32(initData[offset:offset + 32]));
            tokens[i] = address(bytes20(initData[offset + 32:offset + 52]));
        }

        data = initData[32 + count * 52:];
    }

    /// @notice Decodes the origin ops requirement configuration from the initialization data
    /// @dev Each OriginOpsConfig: 32 (chainId) + 1 (requireOriginOps) = 33 bytes
    /// @param initData The initialization data containing origin ops requirement configs
    /// @return requireFlags Array of bool flags
    /// @return chainIds Array of chainIds corresponding to configs
    /// @return data The remaining initialization data after decoding
    function decodeOriginOpsConfig(bytes calldata initData)
        internal
        pure
        returns (bool[] memory requireFlags, uint256[] memory chainIds, bytes calldata data)
    {
        uint256 count = uint256(bytes32(initData[0:32]));
        requireFlags = new bool[](count);
        chainIds = new uint256[](count);

        for (uint256 i = 0; i < count; i++) {
            uint256 offset = 32 + i * 33;
            chainIds[i] = uint256(bytes32(initData[offset:offset + 32]));
            requireFlags[i] = uint8(initData[offset + 32]) != 0;
        }

        data = initData[32 + count * 33:];
    }

    /// @notice Decodes the dest ops requirement configuration from the initialization data
    /// @dev Each DestOpsConfig: 32 (targetChainId) + 1 (requireDestOps) = 33 bytes
    /// @param initData The initialization data containing dest ops requirement configs
    /// @return requireFlags Array of bool flags
    /// @return chainIds Array of targetChainIds corresponding to configs
    /// @return data The remaining initialization data after decoding
    function decodeDestOpsConfig(bytes calldata initData)
        internal
        pure
        returns (bool[] memory requireFlags, uint256[] memory chainIds, bytes calldata data)
    {
        uint256 count = uint256(bytes32(initData[0:32]));
        requireFlags = new bool[](count);
        chainIds = new uint256[](count);

        for (uint256 i = 0; i < count; i++) {
            uint256 offset = 32 + i * 33;
            chainIds[i] = uint256(bytes32(initData[offset:offset + 32]));
            requireFlags[i] = uint8(initData[offset + 32]) != 0;
        }

        data = initData[32 + count * 33:];
    }

    /// @notice Decodes the qualification configuration from the initialization data
    /// @dev Format: count (32) + [chainId (32) + typehash (32) + rootNodeIndex (1) + ruleCount (32)
    /// + rules + packedNodesLength (32) + packedNodes] * count @param initData The initialization
    /// data containing qualification configs
    /// @return configs Array of qualification configurations
    /// @return chainIds Array of chainIds corresponding to configs
    /// @return typehashes Array of typehashes corresponding to configs
    /// @return data The remaining initialization data after decoding
    function decodeQualificationConfig(bytes calldata initData)
        internal
        pure
        returns (
            ParamRules[] memory configs,
            uint256[] memory chainIds,
            bytes32[] memory typehashes,
            bytes calldata data
        )
    {
        uint256 count = uint256(bytes32(initData[0:32]));
        configs = new ParamRules[](count);
        chainIds = new uint256[](count);
        typehashes = new bytes32[](count);
        uint256 offset = 32;

        for (uint256 j = 0; j < count; j++) {
            // Decode chainId
            chainIds[j] = uint256(bytes32(initData[offset:offset + 32]));
            offset += 32;

            // Decode qualification typehash
            typehashes[j] = bytes32(initData[offset:offset + 32]);
            offset += 32;

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
                offset += 42; // Move to the next rule
            }

            // Decode packed nodes length
            uint256 packedNodesLength = uint256(bytes32(initData[offset:offset + 32]));
            offset += 32;

            uint256[] memory packedNodes = new uint256[](packedNodesLength);
            for (uint256 i = 0; i < packedNodesLength; i++) {
                packedNodes[i] = uint256(bytes32(initData[offset:offset + 32]));
                offset += 32;
            }

            configs[j] = ParamRules({
                rootNodeIndex: rootNodeIndex, rules: paramRules, packedNodes: packedNodes
            });
        }

        data = initData[offset:];
    }

    /// @notice Decodes sub-policy configurations from the initialization data
    /// @dev Format: count (32) + [fieldId (1) + policyAddress (20) + initDataLength (32) +
    /// initData] * count @param initData The initialization data containing sub-policy configs
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

    /// @notice Packs tokenIn config into bytes32
    /// @param token Token address
    /// @param lockTag Lock tag
    /// @return packed Packed bytes32 value
    function packTokenIn(
        address token,
        bytes12 lockTag
    )
        internal
        pure
        returns (bytes32 packed)
    {
        // address (20 bytes) in lower bits, lockTag (12 bytes) in upper bits
        packed = bytes32(uint256(uint160(token))) | (bytes32(lockTag) >> 160);
    }

    /// @notice Unpacks tokenIn config from bytes32
    /// @param packed Packed bytes32 value
    /// @return token Token address
    /// @return lockTag Lock tag
    function unpackTokenIn(bytes32 packed) internal pure returns (address token, bytes12 lockTag) {
        token = address(uint160(uint256(packed)));
        lockTag = bytes12(packed << 160);
    }
}
