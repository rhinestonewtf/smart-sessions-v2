// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import { BaseClaimPolicy_Unit_Test } from "../BaseClaimPolicy.t.sol";

/// @title BaseClaimPolicy.getTokensOut Unit Tests
/// @notice Unit tests for the getTokensOut function
contract BaseClaimPolicy_getTokensOut_Unit_Test is BaseClaimPolicy_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test returns empty array when not initialized
    function test_getTokensOut_notInitialized() external view {
        // Act
        address[] memory tokens = policy.getTokensOut(configId, account, chainId1);

        // Assert
        assertEq(tokens.length, 0);
    }

    /// @notice Test returns single token after initialization
    function test_getTokensOut_singleToken() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_TOKEN_OUT, MODE_CHECK_STORAGE);
        uint256[] memory chainIds = new uint256[](1);
        address[] memory tokens = new address[](1);
        chainIds[0] = chainId1;
        tokens[0] = token1;
        bytes memory initData =
            abi.encodePacked(modeConfig, _encodeTokenOutConfig(chainIds, tokens));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);
        address[] memory result = policy.getTokensOut(configId, account, chainId1);

        // Assert
        assertEq(result.length, 1);
        assertEq(result[0], token1);
    }

    /// @notice Test returns multiple tokens for same chainId
    function test_getTokensOut_multipleTokens() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_TOKEN_OUT, MODE_CHECK_STORAGE);
        uint256[] memory chainIds = new uint256[](3);
        address[] memory tokens = new address[](3);
        chainIds[0] = chainId1;
        chainIds[1] = chainId1;
        chainIds[2] = chainId1;
        tokens[0] = token1;
        tokens[1] = token2;
        tokens[2] = token3;
        bytes memory initData =
            abi.encodePacked(modeConfig, _encodeTokenOutConfig(chainIds, tokens));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);
        address[] memory result = policy.getTokensOut(configId, account, chainId1);

        // Assert
        assertEq(result.length, 3);
        assertTrue(_contains(result, token1));
        assertTrue(_contains(result, token2));
        assertTrue(_contains(result, token3));
    }

    /// @notice Test returns empty array for unconfigured chainId
    function test_getTokensOut_unconfiguredChainId() external {
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
        address[] memory result = policy.getTokensOut(configId, account, chainId2);

        // Assert
        assertEq(result.length, 0);
    }

    /// @notice Test with CATCHALL mode (chainId 0)
    function test_getTokensOut_catchallMode() external {
        // Arrange
        uint32 modeConfig = _buildModeConfig(FIELD_TOKEN_OUT, MODE_CHECK_CATCHALL);
        uint256[] memory chainIds = new uint256[](1);
        address[] memory tokens = new address[](1);
        chainIds[0] = 0; // Catchall
        tokens[0] = token1;
        bytes memory initData =
            abi.encodePacked(modeConfig, _encodeTokenOutConfig(chainIds, tokens));

        // Act
        policy.initializeWithMultiplexer(account, configId, initData);
        address[] memory result = policy.getTokensOut(configId, account, 0);

        // Assert
        assertEq(result.length, 1);
        assertEq(result[0], token1);
    }

    /*//////////////////////////////////////////////////////////////
                               HELPERS
    //////////////////////////////////////////////////////////////*/

    function _contains(address[] memory arr, address value) internal pure returns (bool) {
        for (uint256 i = 0; i < arr.length; i++) {
            if (arr[i] == value) return true;
        }
        return false;
    }
}
