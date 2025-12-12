// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import { CompactClaimPolicy_Unit_Test } from "../CompactClaimPolicy.t.sol";

// Libraries
import { BaseConfigLib } from "@policies/claim/base/lib/BaseConfigLib.sol";

// Types
import { FIELD_TOKEN_IN, MODE_CHECK_STORAGE } from "@policies/claim/base/types/BaseDataTypes.sol";

/// @title CompactClaimPolicy.isTokenInWhitelisted Unit Tests
/// @notice Unit tests for the isTokenInWhitelisted function
contract CompactClaimPolicy_isTokenInWhitelisted_Unit_Test is CompactClaimPolicy_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using BaseConfigLib for uint32;

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test returns false when not initialized
    function test_isTokenInWhitelisted_notInitialized() external view {
        // Act
        bool isWhitelisted = compactClaimPolicy.isTokenInWhitelisted(
            configId, account, CHAIN_ID_1, token1, LOCK_TAG_1
        );

        // Assert
        assertFalse(isWhitelisted);
    }

    /// @notice Test returns true for whitelisted token
    function test_isTokenInWhitelisted_whitelisted() external {
        // Arrange
        uint32 modeConfig = uint32(0).setFieldMode(FIELD_TOKEN_IN, MODE_CHECK_STORAGE);
        uint256[] memory chainIds = new uint256[](1);
        bytes32[] memory ids = new bytes32[](1);
        chainIds[0] = CHAIN_ID_1;
        ids[0] = _packTokenId(token1, LOCK_TAG_1);
        bytes memory initData = abi.encodePacked(modeConfig, _encodeTokenInConfig(chainIds, ids));
        compactClaimPolicy.initializeWithMultiplexer(account, configId, initData);

        // Act
        bool isWhitelisted = compactClaimPolicy.isTokenInWhitelisted(
            configId, account, CHAIN_ID_1, token1, LOCK_TAG_1
        );

        // Assert
        assertTrue(isWhitelisted);
    }

    /// @notice Test returns false for non-whitelisted token
    function test_isTokenInWhitelisted_notWhitelisted() external {
        // Arrange
        uint32 modeConfig = uint32(0).setFieldMode(FIELD_TOKEN_IN, MODE_CHECK_STORAGE);
        uint256[] memory chainIds = new uint256[](1);
        bytes32[] memory ids = new bytes32[](1);
        chainIds[0] = CHAIN_ID_1;
        ids[0] = _packTokenId(token1, LOCK_TAG_1);
        bytes memory initData = abi.encodePacked(modeConfig, _encodeTokenInConfig(chainIds, ids));
        compactClaimPolicy.initializeWithMultiplexer(account, configId, initData);

        // Act
        bool isWhitelisted = compactClaimPolicy.isTokenInWhitelisted(
            configId, account, CHAIN_ID_1, token2, LOCK_TAG_2
        );

        // Assert
        assertFalse(isWhitelisted);
    }

    /// @notice Test returns false for same token with different lockTag
    function test_isTokenInWhitelisted_differentLockTag() external {
        // Arrange
        uint32 modeConfig = uint32(0).setFieldMode(FIELD_TOKEN_IN, MODE_CHECK_STORAGE);
        uint256[] memory chainIds = new uint256[](1);
        bytes32[] memory ids = new bytes32[](1);
        chainIds[0] = CHAIN_ID_1;
        ids[0] = _packTokenId(token1, LOCK_TAG_1);
        bytes memory initData = abi.encodePacked(modeConfig, _encodeTokenInConfig(chainIds, ids));
        compactClaimPolicy.initializeWithMultiplexer(account, configId, initData);

        // Act
        bool isWhitelisted = compactClaimPolicy.isTokenInWhitelisted(
            configId, account, CHAIN_ID_1, token1, LOCK_TAG_2
        );

        // Assert
        assertFalse(isWhitelisted);
    }

    /// @notice Test returns false for different chainId
    function test_isTokenInWhitelisted_differentChainId() external {
        // Arrange
        uint32 modeConfig = uint32(0).setFieldMode(FIELD_TOKEN_IN, MODE_CHECK_STORAGE);
        uint256[] memory chainIds = new uint256[](1);
        bytes32[] memory ids = new bytes32[](1);
        chainIds[0] = CHAIN_ID_1;
        ids[0] = _packTokenId(token1, LOCK_TAG_1);
        bytes memory initData = abi.encodePacked(modeConfig, _encodeTokenInConfig(chainIds, ids));
        compactClaimPolicy.initializeWithMultiplexer(account, configId, initData);

        // Act
        bool isWhitelisted = compactClaimPolicy.isTokenInWhitelisted(
            configId, account, CHAIN_ID_2, token1, LOCK_TAG_1
        );

        // Assert
        assertFalse(isWhitelisted);
    }

    /// @notice Test storage isolation per account
    function test_isTokenInWhitelisted_isolatedPerAccount() external {
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
        bool isWhitelistedAccount1 = compactClaimPolicy.isTokenInWhitelisted(
            configId, account, CHAIN_ID_1, token1, LOCK_TAG_1
        );
        bool isWhitelistedAccount2 = compactClaimPolicy.isTokenInWhitelisted(
            configId, account2, CHAIN_ID_1, token1, LOCK_TAG_1
        );

        // Assert
        assertTrue(isWhitelistedAccount1);
        assertFalse(isWhitelistedAccount2);
    }
}
