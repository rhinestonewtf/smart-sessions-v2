// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Mocks
import { MockBaseClaimPolicy } from "@mocks/MockBaseClaimPolicy.sol";
import { MockSubPolicy } from "@mocks/MockSubPolicy.sol";
import { InvalidSubPolicy } from "@mocks/InvalidSubPolicy.sol";

// Dependencies
import { Base_Test } from "@test/Base.t.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import {
    FIELD_ARBITER as FILED_ARBITER_CONSTANT,
    FIELD_EXPIRY as FIELD_EXPIRY_CONSTANT,
    FIELD_TOKEN_IN as FIELD_TOKEN_IN_CONSTANT,
    FIELD_RECIPIENT as FIELD_RECIPIENT_CONSTANT,
    FIELD_FILL_EXPIRY as FIELD_FILL_EXPIRY_CONSTANT,
    FIELD_TOKEN_OUT as FIELD_TOKEN_OUT_CONSTANT,
    FIELD_ORIGIN_OPS as FIELD_ORIGIN_OPS_CONSTANT,
    FIELD_DEST_OPS as FIELD_DEST_OPS_CONSTANT,
    FIELD_QUALIFICATION as FIELD_QUALIFICATION_CONSTANT,
    FIELD_RECIPIENT_IS_SPONSOR as FIELD_RECIPIENT_IS_SPONSOR_CONSTANT,
    MODE_SKIP as MODE_SKIP_CONSTANT,
    MODE_CHECK_STORAGE as MODE_CHECK_STORAGE_CONSTANT,
    MODE_CHECK_CATCHALL as MODE_CHECK_CATCHALL_CONSTANT,
    MODE_CHECK_SUBPOLICY as MODE_CHECK_SUBPOLICY_CONSTANT,
    QualificationRulesStorage,
    PolicyConfig
} from "@policies/claim/base/types/BaseDataTypes.sol";

/// @title BaseClaimPolicy Unit Test Base
/// @notice Base test contract for BaseClaimPolicy unit tests
abstract contract BaseClaimPolicy_Unit_Test is Base_Test {
    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Mode values
    uint8 internal constant MODE_SKIP = MODE_SKIP_CONSTANT;
    uint8 internal constant MODE_CHECK_STORAGE = MODE_CHECK_STORAGE_CONSTANT;
    uint8 internal constant MODE_CHECK_CATCHALL = MODE_CHECK_CATCHALL_CONSTANT;
    uint8 internal constant MODE_CHECK_SUBPOLICY = MODE_CHECK_SUBPOLICY_CONSTANT;

    /// @notice Field IDs
    uint8 internal constant FIELD_ARBITER = FILED_ARBITER_CONSTANT;
    uint8 internal constant FIELD_EXPIRY = FIELD_EXPIRY_CONSTANT;
    uint8 internal constant FIELD_TOKEN_IN = FIELD_TOKEN_IN_CONSTANT;
    uint8 internal constant FIELD_RECIPIENT = FIELD_RECIPIENT_CONSTANT;
    uint8 internal constant FIELD_FILL_EXPIRY = FIELD_FILL_EXPIRY_CONSTANT;
    uint8 internal constant FIELD_TOKEN_OUT = FIELD_TOKEN_OUT_CONSTANT;
    uint8 internal constant FIELD_ORIGIN_OPS = FIELD_ORIGIN_OPS_CONSTANT;
    uint8 internal constant FIELD_DEST_OPS = FIELD_DEST_OPS_CONSTANT;
    uint8 internal constant FIELD_QUALIFICATION = FIELD_QUALIFICATION_CONSTANT;
    uint8 internal constant FIELD_RECIPIENT_IS_SPONSOR = FIELD_RECIPIENT_IS_SPONSOR_CONSTANT;

    /// @notice Default minimal config (modeConfig with all fields set to MODE_SKIP except
    /// recipientIsSponsor set to MODE_CHECK_STORAGE)
    PolicyConfig internal constant DEFAULT_MINIMAL_CONFIG = PolicyConfig.wrap(
        uint32(
            (uint32(MODE_SKIP) << (FIELD_ARBITER * 2)) | (uint32(MODE_SKIP) << (FIELD_EXPIRY * 2))
                | (uint32(MODE_SKIP) << (FIELD_TOKEN_IN * 2))
                | (uint32(MODE_SKIP) << (FIELD_RECIPIENT * 2))
                | (uint32(MODE_SKIP) << (FIELD_FILL_EXPIRY * 2))
                | (uint32(MODE_SKIP) << (FIELD_TOKEN_OUT * 2))
                | (uint32(MODE_SKIP) << (FIELD_ORIGIN_OPS * 2))
                | (uint32(MODE_SKIP) << (FIELD_DEST_OPS * 2))
                | (uint32(MODE_CHECK_STORAGE) << (FIELD_RECIPIENT_IS_SPONSOR * 2))
        )
    );

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    MockBaseClaimPolicy internal policy;
    MockSubPolicy internal mockSubPolicy;
    InvalidSubPolicy internal invalidSubPolicy;

    ConfigId internal configId;
    address internal account;

    // Test addresses
    address internal arbiter1;
    address internal arbiter2;
    address internal arbiter3;
    address internal recipient1;
    address internal recipient2;
    address internal token1;
    address internal token2;
    address internal token3;

    // Test chain IDs
    uint256 internal chainId1;
    uint256 internal chainId2;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        // Deploy contracts
        policy = new MockBaseClaimPolicy();
        mockSubPolicy = new MockSubPolicy();
        invalidSubPolicy = new InvalidSubPolicy();

        // Set up test values
        configId = ConfigId.wrap(bytes32(uint256(1)));
        account = makeAddr("account");

        // Set up test addresses
        arbiter1 = makeAddr("arbiter1");
        arbiter2 = makeAddr("arbiter2");
        arbiter3 = makeAddr("arbiter3");
        recipient1 = makeAddr("recipient1");
        recipient2 = makeAddr("recipient2");
        token1 = makeAddr("token1");
        token2 = makeAddr("token2");
        token3 = makeAddr("token3");

        // Set up test chain IDs
        chainId1 = 1;
        chainId2 = 10;
    }

    /*//////////////////////////////////////////////////////////////
                          MODE CONFIG HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Builds a modeConfig with a single field enabled
    /// @param fieldId The field ID (0-8)
    /// @param mode The mode value (0-3)
    /// @return modeConfig The packed mode configuration
    function _buildModeConfig(uint8 fieldId, uint8 mode) internal pure returns (uint32) {
        return uint32(mode) << (fieldId * 2);
    }

    /// @notice Builds a modeConfig with multiple fields enabled
    /// @param fieldIds Array of field IDs
    /// @param modes Array of mode values
    /// @return modeConfig The packed mode configuration
    function _buildModeConfig(
        uint8[] memory fieldIds,
        uint8[] memory modes
    )
        internal
        pure
        returns (uint32 modeConfig)
    {
        require(fieldIds.length == modes.length, "Length mismatch");
        for (uint256 i = 0; i < fieldIds.length; i++) {
            modeConfig |= uint32(modes[i]) << (fieldIds[i] * 2);
        }
    }

    /*//////////////////////////////////////////////////////////////
                         FIELD ENCODING HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Encodes arbiter configuration
    /// @param arbiters Array of arbiter addresses
    /// @return Encoded arbiter config
    function _encodeArbiterConfig(address[] memory arbiters) internal pure returns (bytes memory) {
        bytes memory encoded = abi.encodePacked(uint8(arbiters.length));
        for (uint256 i = 0; i < arbiters.length; i++) {
            encoded = abi.encodePacked(encoded, arbiters[i]);
        }
        return encoded;
    }

    /// @notice Encodes expiry configuration
    /// @param minExpiry Minimum expiry timestamp
    /// @param maxExpiry Maximum expiry timestamp
    /// @return Encoded expiry config
    function _encodeExpiryConfig(
        uint128 minExpiry,
        uint128 maxExpiry
    )
        internal
        pure
        returns (bytes memory)
    {
        // Pack as uint256: lower 128 bits = min, upper 128 bits = max
        uint256 packed = uint256(minExpiry) | (uint256(maxExpiry) << 128);
        return abi.encodePacked(packed);
    }

    /// @notice Encodes recipient configuration
    /// @param chainIds Array of chain IDs
    /// @param recipients Array of recipient addresses
    /// @return Encoded recipient config
    function _encodeRecipientConfig(
        uint256[] memory chainIds,
        address[] memory recipients
    )
        internal
        pure
        returns (bytes memory)
    {
        require(chainIds.length == recipients.length, "Length mismatch");
        bytes memory encoded = abi.encodePacked(uint8(chainIds.length));
        for (uint256 i = 0; i < chainIds.length; i++) {
            encoded = abi.encodePacked(encoded, chainIds[i], recipients[i]);
        }
        return encoded;
    }

    /// @notice Encodes fill expiry configuration
    /// @param chainIds Array of chain IDs
    /// @param minExpiries Array of minimum fill expiry timestamps
    /// @param maxExpiries Array of maximum fill expiry timestamps
    /// @return Encoded fill expiry config
    function _encodeFillExpiryConfig(
        uint256[] memory chainIds,
        uint128[] memory minExpiries,
        uint128[] memory maxExpiries
    )
        internal
        pure
        returns (bytes memory)
    {
        require(chainIds.length == minExpiries.length, "Length mismatch");
        require(chainIds.length == maxExpiries.length, "Length mismatch");
        bytes memory encoded = abi.encodePacked(uint8(chainIds.length));
        for (uint256 i = 0; i < chainIds.length; i++) {
            // Pack as uint256: lower 128 bits = min, upper 128 bits = max
            uint256 packed = uint256(minExpiries[i]) | (uint256(maxExpiries[i]) << 128);
            encoded = abi.encodePacked(encoded, chainIds[i], packed);
        }
        return encoded;
    }

    /// @notice Encodes token out configuration
    /// @param chainIds Array of chain IDs
    /// @param tokens Array of token addresses
    /// @return Encoded token out config
    function _encodeTokenOutConfig(
        uint256[] memory chainIds,
        address[] memory tokens
    )
        internal
        pure
        returns (bytes memory)
    {
        require(chainIds.length == tokens.length, "Length mismatch");
        bytes memory encoded = abi.encodePacked(uint8(chainIds.length));
        for (uint256 i = 0; i < chainIds.length; i++) {
            encoded = abi.encodePacked(encoded, chainIds[i], tokens[i]);
        }
        return encoded;
    }

    /// @notice Encodes origin ops configuration
    /// @param chainIds Array of chain IDs
    /// @param required Array of required flags
    /// @return Encoded origin ops config
    function _encodeOriginOpsConfig(
        uint256[] memory chainIds,
        bool[] memory required
    )
        internal
        pure
        returns (bytes memory)
    {
        require(chainIds.length == required.length, "Length mismatch");
        bytes memory encoded = abi.encodePacked(uint8(chainIds.length));
        for (uint256 i = 0; i < chainIds.length; i++) {
            encoded = abi.encodePacked(encoded, chainIds[i], required[i]);
        }
        return encoded;
    }

    /// @notice Encodes dest ops configuration
    /// @param chainIds Array of chain IDs
    /// @param required Array of required flags
    /// @return Encoded dest ops config
    function _encodeDestOpsConfig(
        uint256[] memory chainIds,
        bool[] memory required
    )
        internal
        pure
        returns (bytes memory)
    {
        require(chainIds.length == required.length, "Length mismatch");
        bytes memory encoded = abi.encodePacked(uint8(chainIds.length));
        for (uint256 i = 0; i < chainIds.length; i++) {
            encoded = abi.encodePacked(encoded, chainIds[i], required[i]);
        }
        return encoded;
    }

    /// @notice Encodes qualification configuration for a single chainId/arbiter pair
    /// @param chainId The chain ID
    /// @param arbiter The arbiter address
    /// @param useArbiterHash Whether to use arbiter's qualification hash
    /// @return Encoded qualification config with minimal valid rules
    function _encodeQualificationConfig(
        uint256 chainId,
        address arbiter,
        bool useArbiterHash
    )
        internal
        pure
        returns (bytes memory)
    {
        // Minimal valid qualification config:
        // - rootNodeIndex: 0
        // - 1 rule: condition=0 (EQUAL), offset=0, length=32, ref=bytes32(0)
        // - 1 packed node: 0 (RULE node pointing to rule index 0)

        uint8 rootNodeIndex = 0;
        uint8 ruleCount = 1;
        uint8 condition = 0; // EQUAL
        uint64 offset = 0;
        uint8 length = 32;
        bytes32 ref = bytes32(0);
        uint8 packedNodesCount = 1;
        uint256 packedNode = 0; // RULE node type (bits 7:6 = 00), rule index 0 (bits 5:0 = 0)

        return abi.encodePacked(
            uint8(1), // count
            chainId,
            arbiter,
            useArbiterHash,
            rootNodeIndex,
            ruleCount,
            condition,
            offset,
            length,
            ref,
            packedNodesCount,
            packedNode
        );
    }

    /// @notice Encodes qualification configuration for multiple chainId/arbiter pairs
    function _encodeQualificationConfigMultiple(
        uint256[] memory chainIds,
        address[] memory arbiters,
        bool[] memory useArbiterHashes
    )
        internal
        pure
        returns (bytes memory)
    {
        require(chainIds.length == arbiters.length, "Length mismatch");
        require(chainIds.length == useArbiterHashes.length, "Length mismatch");

        bytes memory encoded = abi.encodePacked(uint8(chainIds.length));

        for (uint256 i = 0; i < chainIds.length; i++) {
            // Minimal valid rules for each entry
            uint8 rootNodeIndex = 0;
            uint8 ruleCount = 1;
            uint8 condition = 0;
            uint64 offset = 0;
            uint8 length = 32;
            bytes32 ref = bytes32(0);
            uint8 packedNodesCount = 1;
            uint256 packedNode = 0;

            encoded = abi.encodePacked(
                encoded,
                chainIds[i],
                arbiters[i],
                useArbiterHashes[i],
                rootNodeIndex,
                ruleCount,
                condition,
                offset,
                length,
                ref,
                packedNodesCount,
                packedNode
            );
        }
        return encoded;
    }

    /// @notice Encodes subpolicy configuration
    /// @param fieldId The field ID
    /// @param subPolicyAddr The subpolicy contract address
    /// @param initData The initialization data for the subpolicy
    /// @return Encoded subpolicy config
    function _encodeSubPolicyConfig(
        uint8 fieldId,
        address subPolicyAddr,
        bytes memory initData
    )
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            uint8(1), // count
            fieldId,
            subPolicyAddr,
            uint256(initData.length),
            initData
        );
    }

    /// @notice Encodes multiple subpolicy configurations
    /// @param fieldIds Array of field IDs
    /// @param subPolicyAddrs Array of subpolicy contract addresses
    /// @param initDatas Array of initialization data
    /// @return Encoded subpolicy config
    function _encodeSubPolicyConfigMultiple(
        uint8[] memory fieldIds,
        address[] memory subPolicyAddrs,
        bytes[] memory initDatas
    )
        internal
        pure
        returns (bytes memory)
    {
        require(fieldIds.length == subPolicyAddrs.length, "Length mismatch");
        require(fieldIds.length == initDatas.length, "Length mismatch");

        bytes memory encoded = abi.encodePacked(uint8(fieldIds.length));
        for (uint256 i = 0; i < fieldIds.length; i++) {
            encoded = abi.encodePacked(
                encoded, fieldIds[i], subPolicyAddrs[i], uint256(initDatas[i].length), initDatas[i]
            );
        }
        return encoded;
    }
}
