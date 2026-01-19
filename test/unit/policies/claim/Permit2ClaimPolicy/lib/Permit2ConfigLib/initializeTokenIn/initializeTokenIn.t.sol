// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import { Permit2ConfigLib_Unit_Test } from "../Permit2ConfigLib.t.sol";

/// @title Permit2ConfigLib.initializeTokenIn Unit Tests
/// @notice Unit tests for the initializeTokenIn function
contract Permit2ConfigLib_initializeTokenIn_Unit_Test is Permit2ConfigLib_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test initializes single tokenIn entry
    function test_initializeTokenIn_singleEntry() external {
        // Arrange
        uint256[] memory chainIds = new uint256[](1);
        address[] memory tokens = new address[](1);
        chainIds[0] = CHAIN_ID_1;
        tokens[0] = token1;
        bytes memory initData = _encodeTokenInConfig(chainIds, tokens);

        // Act
        this.initializeTokenIn(initData);

        // Assert
        assertTrue(this.containsTokenIn(CHAIN_ID_1, token1));
        assertEq(this.tokenInSetLength(CHAIN_ID_1), 1);
    }

    /// @notice Test initializes multiple tokenIn entries on same chain
    function test_initializeTokenIn_multipleEntriesSameChain() external {
        // Arrange
        uint256[] memory chainIds = new uint256[](3);
        address[] memory tokens = new address[](3);
        chainIds[0] = CHAIN_ID_1;
        chainIds[1] = CHAIN_ID_1;
        chainIds[2] = CHAIN_ID_1;
        tokens[0] = token1;
        tokens[1] = token2;
        tokens[2] = token3;
        bytes memory initData = _encodeTokenInConfig(chainIds, tokens);

        // Act
        this.initializeTokenIn(initData);

        // Assert
        assertEq(this.tokenInSetLength(CHAIN_ID_1), 3);
        assertTrue(this.containsTokenIn(CHAIN_ID_1, token1));
        assertTrue(this.containsTokenIn(CHAIN_ID_1, token2));
        assertTrue(this.containsTokenIn(CHAIN_ID_1, token3));
    }

    /// @notice Test initializes entries on different chains
    function test_initializeTokenIn_differentChains() external {
        // Arrange
        uint256[] memory chainIds = new uint256[](2);
        address[] memory tokens = new address[](2);
        chainIds[0] = CHAIN_ID_1;
        chainIds[1] = CHAIN_ID_2;
        tokens[0] = token1;
        tokens[1] = token2;
        bytes memory initData = _encodeTokenInConfig(chainIds, tokens);

        // Act
        this.initializeTokenIn(initData);

        // Assert
        assertEq(this.tokenInSetLength(CHAIN_ID_1), 1);
        assertEq(this.tokenInSetLength(CHAIN_ID_2), 1);
        assertTrue(this.containsTokenIn(CHAIN_ID_1, token1));
        assertTrue(this.containsTokenIn(CHAIN_ID_2, token2));
    }

    /// @notice Test returns remaining calldata
    function test_initializeTokenIn_returnsRemaining() external {
        // Arrange
        uint256[] memory chainIds = new uint256[](1);
        address[] memory tokens = new address[](1);
        chainIds[0] = CHAIN_ID_1;
        tokens[0] = token1;
        bytes memory tokenInData = _encodeTokenInConfig(chainIds, tokens);
        bytes memory extraData = hex"deadbeef";
        bytes memory initData = abi.encodePacked(tokenInData, extraData);

        // Act
        uint256 remainingLength = this.initializeTokenIn(initData);

        // Assert
        assertEq(remainingLength, extraData.length);
    }

    /// @notice Test with zero count
    function test_initializeTokenIn_zeroCount() external {
        // Arrange
        bytes memory extraData = hex"cafebabe";
        bytes memory initData = abi.encodePacked(uint8(0), extraData);

        // Act
        uint256 remainingLength = this.initializeTokenIn(initData);

        // Assert
        assertEq(this.tokenInSetLength(CHAIN_ID_1), 0);
        assertEq(remainingLength, extraData.length);
    }

    /// @notice Test duplicate token on same chain
    function test_initializeTokenIn_duplicateToken() external {
        // Arrange
        uint256[] memory chainIds = new uint256[](2);
        address[] memory tokens = new address[](2);
        chainIds[0] = CHAIN_ID_1;
        chainIds[1] = CHAIN_ID_1;
        tokens[0] = token1;
        tokens[1] = token1;
        bytes memory initData = _encodeTokenInConfig(chainIds, tokens);

        // Act
        this.initializeTokenIn(initData);

        // Assert - EnumerableSet deduplicates
        assertEq(this.tokenInSetLength(CHAIN_ID_1), 1);
        assertTrue(this.containsTokenIn(CHAIN_ID_1, token1));
    }
}
