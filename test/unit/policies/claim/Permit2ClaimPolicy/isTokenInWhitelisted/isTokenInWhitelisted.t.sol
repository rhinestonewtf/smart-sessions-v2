// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import { Permit2ClaimPolicy_Unit_Test } from "../Permit2ClaimPolicy.t.sol";

// Libraries
import { BaseConfigLib } from "@policies/claim/base/lib/BaseConfigLib.sol";

// Types
import { FIELD_TOKEN_IN, MODE_CHECK_STORAGE } from "@policies/claim/base/types/BaseDataTypes.sol";

/// @title Permit2ClaimPolicy.isTokenInWhitelisted Unit Tests
/// @notice Unit tests for the isTokenInWhitelisted function
contract Permit2ClaimPolicy_isTokenInWhitelisted_Unit_Test is Permit2ClaimPolicy_Unit_Test {
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
        bool isWhitelisted =
            permit2ClaimPolicy.isTokenInWhitelisted(configId, account, CHAIN_ID_1, token1);

        // Assert
        assertFalse(isWhitelisted);
    }

    /// @notice Test returns true for whitelisted token
    function test_isTokenInWhitelisted_whitelisted() external {
        // Arrange
        uint32 modeConfig = uint32(0).setFieldMode(FIELD_TOKEN_IN, MODE_CHECK_STORAGE);
        uint256[] memory chainIds = new uint256[](1);
        address[] memory tokens = new address[](1);
        chainIds[0] = CHAIN_ID_1;
        tokens[0] = token1;
        bytes memory initData = abi.encodePacked(modeConfig, _encodeTokenInConfig(chainIds, tokens));
        permit2ClaimPolicy.initializeWithMultiplexer(account, configId, initData);

        // Act
        bool isWhitelisted =
            permit2ClaimPolicy.isTokenInWhitelisted(configId, account, CHAIN_ID_1, token1);

        // Assert
        assertTrue(isWhitelisted);
    }

    /// @notice Test returns false for non-whitelisted token
    function test_isTokenInWhitelisted_notWhitelisted() external {
        // Arrange
        uint32 modeConfig = uint32(0).setFieldMode(FIELD_TOKEN_IN, MODE_CHECK_STORAGE);
        uint256[] memory chainIds = new uint256[](1);
        address[] memory tokens = new address[](1);
        chainIds[0] = CHAIN_ID_1;
        tokens[0] = token1;
        bytes memory initData = abi.encodePacked(modeConfig, _encodeTokenInConfig(chainIds, tokens));
        permit2ClaimPolicy.initializeWithMultiplexer(account, configId, initData);

        // Act
        bool isWhitelisted =
            permit2ClaimPolicy.isTokenInWhitelisted(configId, account, CHAIN_ID_1, token2);

        // Assert
        assertFalse(isWhitelisted);
    }

    /// @notice Test returns false for different chainId
    function test_isTokenInWhitelisted_differentChainId() external {
        // Arrange
        uint32 modeConfig = uint32(0).setFieldMode(FIELD_TOKEN_IN, MODE_CHECK_STORAGE);
        uint256[] memory chainIds = new uint256[](1);
        address[] memory tokens = new address[](1);
        chainIds[0] = CHAIN_ID_1;
        tokens[0] = token1;
        bytes memory initData = abi.encodePacked(modeConfig, _encodeTokenInConfig(chainIds, tokens));
        permit2ClaimPolicy.initializeWithMultiplexer(account, configId, initData);

        // Act
        bool isWhitelisted =
            permit2ClaimPolicy.isTokenInWhitelisted(configId, account, CHAIN_ID_2, token1);

        // Assert
        assertFalse(isWhitelisted);
    }

    /// @notice Test storage isolation per account
    function test_isTokenInWhitelisted_isolatedPerAccount() external {
        // Arrange
        address account2 = makeAddr("account2");
        uint32 modeConfig = uint32(0).setFieldMode(FIELD_TOKEN_IN, MODE_CHECK_STORAGE);
        uint256[] memory chainIds = new uint256[](1);
        address[] memory tokens = new address[](1);
        chainIds[0] = CHAIN_ID_1;
        tokens[0] = token1;
        bytes memory initData = abi.encodePacked(modeConfig, _encodeTokenInConfig(chainIds, tokens));
        permit2ClaimPolicy.initializeWithMultiplexer(account, configId, initData);

        // Act
        bool isWhitelistedAccount1 =
            permit2ClaimPolicy.isTokenInWhitelisted(configId, account, CHAIN_ID_1, token1);
        bool isWhitelistedAccount2 =
            permit2ClaimPolicy.isTokenInWhitelisted(configId, account2, CHAIN_ID_1, token1);

        // Assert
        assertTrue(isWhitelistedAccount1);
        assertFalse(isWhitelistedAccount2);
    }
}
