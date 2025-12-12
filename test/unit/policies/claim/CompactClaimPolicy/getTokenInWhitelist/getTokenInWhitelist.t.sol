// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import { CompactClaimPolicy_Unit_Test } from "../CompactClaimPolicy.t.sol";

// Libraries
import { BaseConfigLib } from "@policies/claim/base/lib/BaseConfigLib.sol";

// Types
import { FIELD_TOKEN_IN, MODE_CHECK_STORAGE } from "@policies/claim/base/types/BaseDataTypes.sol";

/// @title CompactClaimPolicy.getTokenInWhitelist Unit Tests
/// @notice Unit tests for the getTokenInWhitelist function
contract CompactClaimPolicy_getTokenInWhitelist_Unit_Test is CompactClaimPolicy_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using BaseConfigLib for uint32;

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test returns empty array when not initialized
    function test_getTokenInWhitelist_notInitialized() external view {
        // Act
        bytes32[] memory tokens =
            compactClaimPolicy.getTokenInWhitelist(configId, account, CHAIN_ID_1);

        // Assert
        assertEq(tokens.length, 0);
    }

    /// @notice Test returns single token after initialization
    function test_getTokenInWhitelist_singleToken() external {
        // Arrange
        uint32 modeConfig = uint32(0).setFieldMode(FIELD_TOKEN_IN, MODE_CHECK_STORAGE);
        uint256[] memory chainIds = new uint256[](1);
        bytes32[] memory ids = new bytes32[](1);
        chainIds[0] = CHAIN_ID_1;
        ids[0] = _packTokenId(token1, LOCK_TAG_1);
        bytes memory initData = abi.encodePacked(modeConfig, _encodeTokenInConfig(chainIds, ids));
        compactClaimPolicy.initializeWithMultiplexer(account, configId, initData);

        // Act
        bytes32[] memory tokens =
            compactClaimPolicy.getTokenInWhitelist(configId, account, CHAIN_ID_1);

        // Assert
        assertEq(tokens.length, 1);
        assertEq(tokens[0], ids[0]);
    }

    /// @notice Test returns multiple tokens after initialization
    function test_getTokenInWhitelist_multipleTokens() external {
        // Arrange
        uint32 modeConfig = uint32(0).setFieldMode(FIELD_TOKEN_IN, MODE_CHECK_STORAGE);
        uint256[] memory chainIds = new uint256[](3);
        bytes32[] memory ids = new bytes32[](3);
        chainIds[0] = CHAIN_ID_1;
        chainIds[1] = CHAIN_ID_1;
        chainIds[2] = CHAIN_ID_1;
        ids[0] = _packTokenId(token1, LOCK_TAG_1);
        ids[1] = _packTokenId(token2, LOCK_TAG_2);
        ids[2] = _packTokenId(token3, LOCK_TAG_3);
        bytes memory initData = abi.encodePacked(modeConfig, _encodeTokenInConfig(chainIds, ids));
        compactClaimPolicy.initializeWithMultiplexer(account, configId, initData);

        // Act
        bytes32[] memory tokens =
            compactClaimPolicy.getTokenInWhitelist(configId, account, CHAIN_ID_1);

        // Assert
        assertEq(tokens.length, 3);
    }

    /// @notice Test returns empty for unconfigured chainId
    function test_getTokenInWhitelist_unconfiguredChainId() external {
        // Arrange
        uint32 modeConfig = uint32(0).setFieldMode(FIELD_TOKEN_IN, MODE_CHECK_STORAGE);
        uint256[] memory chainIds = new uint256[](1);
        bytes32[] memory ids = new bytes32[](1);
        chainIds[0] = CHAIN_ID_1;
        ids[0] = _packTokenId(token1, LOCK_TAG_1);
        bytes memory initData = abi.encodePacked(modeConfig, _encodeTokenInConfig(chainIds, ids));
        compactClaimPolicy.initializeWithMultiplexer(account, configId, initData);

        // Act
        bytes32[] memory tokens =
            compactClaimPolicy.getTokenInWhitelist(configId, account, CHAIN_ID_2);

        // Assert
        assertEq(tokens.length, 0);
    }

    /// @notice Test storage isolation per account
    function test_getTokenInWhitelist_isolatedPerAccount() external {
        // Arrange
        address account2 = makeAddr("account2");
        uint32 modeConfig = uint32(0).setFieldMode(FIELD_TOKEN_IN, MODE_CHECK_STORAGE);

        uint256[] memory chainIds = new uint256[](1);
        bytes32[] memory ids = new bytes32[](1);
        chainIds[0] = CHAIN_ID_1;
        ids[0] = _packTokenId(token1, LOCK_TAG_1);
        bytes memory initData = abi.encodePacked(modeConfig, _encodeTokenInConfig(chainIds, ids));
        compactClaimPolicy.initializeWithMultiplexer(account, configId, initData);

        // Act
        bytes32[] memory tokensAccount1 =
            compactClaimPolicy.getTokenInWhitelist(configId, account, CHAIN_ID_1);
        bytes32[] memory tokensAccount2 =
            compactClaimPolicy.getTokenInWhitelist(configId, account2, CHAIN_ID_1);

        // Assert
        assertEq(tokensAccount1.length, 1);
        assertEq(tokensAccount2.length, 0);
    }
}
