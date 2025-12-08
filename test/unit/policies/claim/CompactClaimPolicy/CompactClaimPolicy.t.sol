// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Testing
import { Base_Test } from "@test/Base.t.sol";

// Contracts
import { CompactClaimPolicy } from "@policies/claim/compact/CompactClaimPolicy.sol";

// Mocks
import { MockBaseClaimPolicy } from "@mocks/MockBaseClaimPolicy.sol";

// Libraries
import { BaseConfigLib } from "@policies/claim/base/lib/BaseConfigLib.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import {
    PolicyConfig,
    MODE_SKIP,
    MODE_CHECK_STORAGE,
    MODE_CHECK_CATCHALL,
    MODE_CHECK_SUBPOLICY,
    FIELD_TOKEN_IN
} from "@policies/claim/base/types/BaseDataTypes.sol";

/// @title CompactClaimPolicy Unit Test Base
/// @notice Base contract for CompactClaimPolicy and lib unit tests
contract CompactClaimPolicy_Unit_Test is Base_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using BaseConfigLib for uint32;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    CompactClaimPolicy internal compactClaimPolicy;
    MockBaseClaimPolicy internal mockSubPolicy;
    ConfigId internal configId;
    address internal account;

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    uint256 internal constant CHAIN_ID_1 = 1;
    uint256 internal constant CHAIN_ID_2 = 42_161;

    address internal token1;
    address internal token2;
    address internal token3;

    bytes12 internal constant LOCK_TAG_1 = bytes12(uint96(1));
    bytes12 internal constant LOCK_TAG_2 = bytes12(uint96(2));
    bytes12 internal constant LOCK_TAG_3 = bytes12(uint96(3));

    bytes32 internal constant HASH = keccak256("test");

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        super.setUp();
        compactClaimPolicy = new CompactClaimPolicy();
        mockSubPolicy = new MockBaseClaimPolicy();
        configId = ConfigId.wrap(bytes32(uint256(1)));
        account = makeAddr("account");
        token1 = makeAddr("token1");
        token2 = makeAddr("token2");
        token3 = makeAddr("token3");
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Builds a PolicyConfig with specified field mode
    function _buildConfig(uint8 fieldId, uint8 mode) internal pure returns (PolicyConfig) {
        uint32 modeConfig = uint32(0).setFieldMode(fieldId, mode);
        return PolicyConfig.wrap(modeConfig);
    }

    /// @notice Packs token and lockTag into a Compact ID
    /// @dev Matches Compact IdLib format: lockTag (96 high) | token (160 low)
    function _packTokenId(address token, bytes12 lockTag) internal pure returns (bytes32) {
        return bytes32(uint256(uint96(lockTag)) << 160 | uint256(uint160(token)));
    }

    /// @notice Encodes tokenIn config for Compact initialization
    /// @dev Layout: [count (1)] + [chainId (32) + id (32)] per entry
    function _encodeTokenInConfig(
        uint256[] memory chainIds,
        bytes32[] memory ids
    )
        internal
        pure
        returns (bytes memory)
    {
        require(chainIds.length == ids.length, "Length mismatch");
        bytes memory encoded = abi.encodePacked(uint8(chainIds.length));
        for (uint256 i = 0; i < chainIds.length; i++) {
            encoded = abi.encodePacked(encoded, chainIds[i], ids[i]);
        }
        return encoded;
    }

    /// @notice Encodes tokenIn array for validation (length + Lock[])
    /// @dev Lock = [id (32 bytes), amount (32 bytes)]
    function _encodeTokenInArray(
        bytes32[] memory ids,
        uint256[] memory amounts
    )
        internal
        pure
        returns (bytes memory)
    {
        require(ids.length == amounts.length, "Length mismatch");
        bytes memory encoded = abi.encodePacked(uint8(ids.length));
        for (uint256 i = 0; i < ids.length; i++) {
            encoded = abi.encodePacked(encoded, ids[i], amounts[i]);
        }
        return encoded;
    }

    /// @notice Encodes a pre-computed hash for SKIP mode
    function _encodeTokenInHash(bytes32 hash) internal pure returns (bytes memory) {
        return abi.encodePacked(hash);
    }
}
