// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import { BaseClaimPolicy_Unit_Test } from "../BaseClaimPolicy.t.sol";

/// @title BaseClaimPolicy.isTokenOutWhitelisted Unit Tests
/// @notice Unit tests for the isTokenOutWhitelisted function
contract BaseClaimPolicy_isTokenOutWhitelisted_Unit_Test is BaseClaimPolicy_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test returns false when not initialized
    function test_isTokenOutWhitelisted_notInitialized() external view {
        // Act
        bool result = policy.isTokenOutWhitelisted(configId, account, chainId1, token1);

        // Assert
        assertFalse(result);
    }

    /// @notice Test returns true for whitelisted token
    function test_isTokenOutWhitelisted_whenWhitelisted() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_TOKEN_OUT, MODE_CHECK_STORAGE);
        uint256[] memory chainIds = new uint256[](1);
        address[] memory tokens = new address[](1);
        chainIds[0] = chainId1;
        tokens[0] = token1;
        bytes memory initData =
            abi.encodePacked(modeConfig, _encodeTokenOutConfig(chainIds, tokens));
        policy.initializeWithMultiplexer(account, configId, initData);

        // Act
        bool result = policy.isTokenOutWhitelisted(configId, account, chainId1, token1);

        // Assert
        assertTrue(result);
    }

    /// @notice Test returns false for non-whitelisted token
    function test_isTokenOutWhitelisted_whenNotWhitelisted() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_TOKEN_OUT, MODE_CHECK_STORAGE);
        uint256[] memory chainIds = new uint256[](1);
        address[] memory tokens = new address[](1);
        chainIds[0] = chainId1;
        tokens[0] = token1;
        bytes memory initData =
            abi.encodePacked(modeConfig, _encodeTokenOutConfig(chainIds, tokens));
        policy.initializeWithMultiplexer(account, configId, initData);

        // Act
        bool result = policy.isTokenOutWhitelisted(configId, account, chainId1, token2);

        // Assert
        assertFalse(result);
    }

    /// @notice Test returns false for wrong chainId
    function test_isTokenOutWhitelisted_wrongChainId() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_TOKEN_OUT, MODE_CHECK_STORAGE);
        uint256[] memory chainIds = new uint256[](1);
        address[] memory tokens = new address[](1);
        chainIds[0] = chainId1;
        tokens[0] = token1;
        bytes memory initData =
            abi.encodePacked(modeConfig, _encodeTokenOutConfig(chainIds, tokens));
        policy.initializeWithMultiplexer(account, configId, initData);

        // Act
        bool result = policy.isTokenOutWhitelisted(configId, account, chainId2, token1);

        // Assert
        assertFalse(result);
    }

    /// @notice Test with multiple tokens
    function test_isTokenOutWhitelisted_multipleTokens() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_TOKEN_OUT, MODE_CHECK_STORAGE);
        uint256[] memory chainIds = new uint256[](2);
        address[] memory tokens = new address[](2);
        chainIds[0] = chainId1;
        chainIds[1] = chainId1;
        tokens[0] = token1;
        tokens[1] = token2;
        bytes memory initData =
            abi.encodePacked(modeConfig, _encodeTokenOutConfig(chainIds, tokens));
        policy.initializeWithMultiplexer(account, configId, initData);

        // Act & Assert
        assertTrue(policy.isTokenOutWhitelisted(configId, account, chainId1, token1));
        assertTrue(policy.isTokenOutWhitelisted(configId, account, chainId1, token2));
        assertFalse(policy.isTokenOutWhitelisted(configId, account, chainId1, token3));
    }

    /// @notice Fuzz test for isTokenOutWhitelisted
    function testFuzz_isTokenOutWhitelisted(
        uint256 _chainId,
        address _token,
        address _checkToken
    )
        external
    {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_TOKEN_OUT, MODE_CHECK_STORAGE);
        uint256[] memory chainIds = new uint256[](1);
        address[] memory tokens = new address[](1);
        chainIds[0] = _chainId;
        tokens[0] = _token;
        bytes memory initData =
            abi.encodePacked(modeConfig, _encodeTokenOutConfig(chainIds, tokens));
        policy.initializeWithMultiplexer(account, configId, initData);

        // Act
        bool result = policy.isTokenOutWhitelisted(configId, account, _chainId, _checkToken);

        // Assert
        assertEq(result, _token == _checkToken);
    }
}
