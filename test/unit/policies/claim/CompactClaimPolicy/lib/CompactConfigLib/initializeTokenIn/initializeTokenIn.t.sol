// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import { CompactConfigLib_Unit_Test } from "../CompactConfigLib.t.sol";

/// @title CompactConfigLib.initializeTokenIn Unit Tests
/// @notice Unit tests for the initializeTokenIn function
contract CompactConfigLib_initializeTokenIn_Unit_Test is CompactConfigLib_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test initializes single tokenIn entry
    function test_initializeTokenIn_singleEntry() external {
        // Arrange
        uint256[] memory chainIds = new uint256[](1);
        bytes32[] memory ids = new bytes32[](1);
        chainIds[0] = CHAIN_ID_1;
        ids[0] = _packTokenId(token1, LOCK_TAG_1);
        bytes memory initData = _encodeTokenInConfig(chainIds, ids);

        // Act
        this.initializeTokenIn(initData);

        // Assert
        assertTrue(this.containsTokenIn(CHAIN_ID_1, ids[0]));
        assertEq(this.tokenInSetLength(CHAIN_ID_1), 1);
    }

    /// @notice Test initializes multiple tokenIn entries on same chain
    function test_initializeTokenIn_multipleEntriesSameChain() external {
        // Arrange
        uint256[] memory chainIds = new uint256[](3);
        bytes32[] memory ids = new bytes32[](3);
        chainIds[0] = CHAIN_ID_1;
        chainIds[1] = CHAIN_ID_1;
        chainIds[2] = CHAIN_ID_1;
        ids[0] = _packTokenId(token1, LOCK_TAG_1);
        ids[1] = _packTokenId(token2, LOCK_TAG_2);
        ids[2] = _packTokenId(token3, LOCK_TAG_3);
        bytes memory initData = _encodeTokenInConfig(chainIds, ids);

        // Act
        this.initializeTokenIn(initData);

        // Assert
        assertEq(this.tokenInSetLength(CHAIN_ID_1), 3);
        assertTrue(this.containsTokenIn(CHAIN_ID_1, ids[0]));
        assertTrue(this.containsTokenIn(CHAIN_ID_1, ids[1]));
        assertTrue(this.containsTokenIn(CHAIN_ID_1, ids[2]));
    }

    /// @notice Test initializes entries on different chains
    function test_initializeTokenIn_differentChains() external {
        // Arrange
        uint256[] memory chainIds = new uint256[](2);
        bytes32[] memory ids = new bytes32[](2);
        chainIds[0] = CHAIN_ID_1;
        chainIds[1] = CHAIN_ID_2;
        ids[0] = _packTokenId(token1, LOCK_TAG_1);
        ids[1] = _packTokenId(token2, LOCK_TAG_2);
        bytes memory initData = _encodeTokenInConfig(chainIds, ids);

        // Act
        this.initializeTokenIn(initData);

        // Assert
        assertEq(this.tokenInSetLength(CHAIN_ID_1), 1);
        assertEq(this.tokenInSetLength(CHAIN_ID_2), 1);
        assertTrue(this.containsTokenIn(CHAIN_ID_1, ids[0]));
        assertTrue(this.containsTokenIn(CHAIN_ID_2, ids[1]));
    }

    /// @notice Test same token with different lockTags
    function test_initializeTokenIn_sameTokenDifferentLockTags() external {
        // Arrange
        uint256[] memory chainIds = new uint256[](2);
        bytes32[] memory ids = new bytes32[](2);
        chainIds[0] = CHAIN_ID_1;
        chainIds[1] = CHAIN_ID_1;
        ids[0] = _packTokenId(token1, LOCK_TAG_1);
        ids[1] = _packTokenId(token1, LOCK_TAG_2);
        bytes memory initData = _encodeTokenInConfig(chainIds, ids);

        // Act
        this.initializeTokenIn(initData);

        // Assert
        assertEq(this.tokenInSetLength(CHAIN_ID_1), 2);
        assertTrue(this.containsTokenIn(CHAIN_ID_1, ids[0]));
        assertTrue(this.containsTokenIn(CHAIN_ID_1, ids[1]));
    }

    /// @notice Test returns remaining calldata
    function test_initializeTokenIn_returnsRemaining() external {
        // Arrange
        uint256[] memory chainIds = new uint256[](1);
        bytes32[] memory ids = new bytes32[](1);
        chainIds[0] = CHAIN_ID_1;
        ids[0] = _packTokenId(token1, LOCK_TAG_1);
        bytes memory tokenInData = _encodeTokenInConfig(chainIds, ids);
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
}
