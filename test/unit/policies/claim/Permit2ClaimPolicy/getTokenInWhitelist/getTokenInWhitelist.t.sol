// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import { Permit2ClaimPolicy_Unit_Test } from "../Permit2ClaimPolicy.t.sol";

// Libraries
import { BaseConfigLib } from "@policies/claim/base/lib/BaseConfigLib.sol";

// Types
import { FIELD_TOKEN_IN, MODE_CHECK_STORAGE } from "@policies/claim/base/types/BaseDataTypes.sol";

/// @title Permit2ClaimPolicy.getTokenInWhitelist Unit Tests
/// @notice Unit tests for the getTokenInWhitelist function
contract Permit2ClaimPolicy_getTokenInWhitelist_Unit_Test is Permit2ClaimPolicy_Unit_Test {
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
        address[] memory tokens =
            permit2ClaimPolicy.getTokenInWhitelist(configId, account, CHAIN_ID_1);

        // Assert
        assertEq(tokens.length, 0);
    }

    /// @notice Test returns single token after initialization
    function test_getTokenInWhitelist_singleToken() external {
        // Arrange
        uint32 modeConfig = uint32(0).setFieldMode(FIELD_TOKEN_IN, MODE_CHECK_STORAGE);
        uint256[] memory chainIds = new uint256[](1);
        address[] memory tokens = new address[](1);
        chainIds[0] = CHAIN_ID_1;
        tokens[0] = token1;
        bytes memory initData = abi.encodePacked(modeConfig, _encodeTokenInConfig(chainIds, tokens));
        permit2ClaimPolicy.initializeWithMultiplexer(account, configId, initData);

        // Act
        address[] memory result =
            permit2ClaimPolicy.getTokenInWhitelist(configId, account, CHAIN_ID_1);

        // Assert
        assertEq(result.length, 1);
        assertEq(result[0], token1);
    }

    /// @notice Test returns multiple tokens after initialization
    function test_getTokenInWhitelist_multipleTokens() external {
        // Arrange
        uint32 modeConfig = uint32(0).setFieldMode(FIELD_TOKEN_IN, MODE_CHECK_STORAGE);
        uint256[] memory chainIds = new uint256[](3);
        address[] memory tokens = new address[](3);
        chainIds[0] = CHAIN_ID_1;
        chainIds[1] = CHAIN_ID_1;
        chainIds[2] = CHAIN_ID_1;
        tokens[0] = token1;
        tokens[1] = token2;
        tokens[2] = token3;
        bytes memory initData = abi.encodePacked(modeConfig, _encodeTokenInConfig(chainIds, tokens));
        permit2ClaimPolicy.initializeWithMultiplexer(account, configId, initData);

        // Act
        address[] memory result =
            permit2ClaimPolicy.getTokenInWhitelist(configId, account, CHAIN_ID_1);

        // Assert
        assertEq(result.length, 3);
    }

    /// @notice Test returns empty for unconfigured chainId
    function test_getTokenInWhitelist_unconfiguredChainId() external {
        // Arrange
        uint32 modeConfig = uint32(0).setFieldMode(FIELD_TOKEN_IN, MODE_CHECK_STORAGE);
        uint256[] memory chainIds = new uint256[](1);
        address[] memory tokens = new address[](1);
        chainIds[0] = CHAIN_ID_1;
        tokens[0] = token1;
        bytes memory initData = abi.encodePacked(modeConfig, _encodeTokenInConfig(chainIds, tokens));
        permit2ClaimPolicy.initializeWithMultiplexer(account, configId, initData);

        // Act
        address[] memory result =
            permit2ClaimPolicy.getTokenInWhitelist(configId, account, CHAIN_ID_2);

        // Assert
        assertEq(result.length, 0);
    }

    /// @notice Test storage isolation per account
    function test_getTokenInWhitelist_isolatedPerAccount() external {
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
        address[] memory tokensAccount1 =
            permit2ClaimPolicy.getTokenInWhitelist(configId, account, CHAIN_ID_1);
        address[] memory tokensAccount2 =
            permit2ClaimPolicy.getTokenInWhitelist(configId, account2, CHAIN_ID_1);

        // Assert
        assertEq(tokensAccount1.length, 1);
        assertEq(tokensAccount2.length, 0);
    }
}

