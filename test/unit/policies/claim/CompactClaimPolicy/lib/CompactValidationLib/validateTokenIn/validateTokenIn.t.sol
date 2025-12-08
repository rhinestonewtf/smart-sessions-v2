// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import { CompactValidationLib_Unit_Test } from "../CompactValidationLib.t.sol";

// Types
import {
    PolicyConfig,
    MODE_SKIP,
    MODE_CHECK_STORAGE,
    MODE_CHECK_CATCHALL,
    MODE_CHECK_SUBPOLICY,
    FIELD_TOKEN_IN
} from "@policies/claim/base/types/BaseDataTypes.sol";

/// @title CompactValidationLib.validateTokenIn Unit Tests
/// @notice Unit tests for the validateTokenIn function
contract CompactValidationLib_validateTokenIn_Unit_Test is CompactValidationLib_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                              SKIP MODE
    //////////////////////////////////////////////////////////////*/

    /// @notice Test SKIP mode returns pre-computed hash
    function test_validateTokenIn_skipMode_returnsHash() external view {
        // Arrange
        PolicyConfig config = _buildConfig(FIELD_TOKEN_IN, MODE_SKIP);
        bytes32 precomputedHash = keccak256("tokenInHash");
        bytes memory data = _encodeTokenInHash(precomputedHash);

        // Act
        (bool valid, bytes32 tokenInHash, uint256 newOffset) =
            this.validateTokenIn(data, 0, CHAIN_ID_1, config);

        // Assert
        assertTrue(valid);
        assertEq(tokenInHash, precomputedHash);
        assertEq(newOffset, 32);
    }

    /*//////////////////////////////////////////////////////////////
                            STORAGE MODE
    //////////////////////////////////////////////////////////////*/

    /// @notice Test STORAGE mode with whitelisted token
    function test_validateTokenIn_storageMode_whitelisted() external {
        // Arrange
        PolicyConfig config = _buildConfig(FIELD_TOKEN_IN, MODE_CHECK_STORAGE);
        bytes32 id = _packTokenId(token1, LOCK_TAG_1);
        this.addTokenToWhitelist(CHAIN_ID_1, id);

        bytes32[] memory ids = new bytes32[](1);
        uint256[] memory amounts = new uint256[](1);
        ids[0] = id;
        amounts[0] = 1000;
        bytes memory data = _encodeTokenInArray(ids, amounts);

        // Act
        (bool valid, bytes32 tokenInHash, uint256 newOffset) =
            this.validateTokenIn(data, 0, CHAIN_ID_1, config);

        // Assert
        assertTrue(valid);
        assertNotEq(tokenInHash, bytes32(0));
        assertEq(newOffset, 1 + 64); // count (1) + 1 entry (64)
    }

    /// @notice Test STORAGE mode with non-whitelisted token
    function test_validateTokenIn_storageMode_notWhitelisted() external {
        // Arrange
        PolicyConfig config = _buildConfig(FIELD_TOKEN_IN, MODE_CHECK_STORAGE);
        bytes32 whitelistedId = _packTokenId(token1, LOCK_TAG_1);
        bytes32 notWhitelistedId = _packTokenId(token2, LOCK_TAG_2);
        this.addTokenToWhitelist(CHAIN_ID_1, whitelistedId);

        bytes32[] memory ids = new bytes32[](1);
        uint256[] memory amounts = new uint256[](1);
        ids[0] = notWhitelistedId;
        amounts[0] = 1000;
        bytes memory data = _encodeTokenInArray(ids, amounts);

        // Act
        (bool valid, bytes32 tokenInHash, uint256 newOffset) =
            this.validateTokenIn(data, 0, CHAIN_ID_1, config);

        // Assert
        assertFalse(valid);
        assertEq(tokenInHash, bytes32(0));
        assertEq(newOffset, 0);
    }

    /// @notice Test STORAGE mode with empty whitelist
    function test_validateTokenIn_storageMode_emptyWhitelist() external view {
        // Arrange
        PolicyConfig config = _buildConfig(FIELD_TOKEN_IN, MODE_CHECK_STORAGE);
        bytes32 id = _packTokenId(token1, LOCK_TAG_1);

        bytes32[] memory ids = new bytes32[](1);
        uint256[] memory amounts = new uint256[](1);
        ids[0] = id;
        amounts[0] = 1000;
        bytes memory data = _encodeTokenInArray(ids, amounts);

        // Act
        (bool valid, bytes32 tokenInHash, uint256 newOffset) =
            this.validateTokenIn(data, 0, CHAIN_ID_1, config);

        // Assert
        assertFalse(valid);
        assertEq(tokenInHash, bytes32(0));
        assertEq(newOffset, 0);
    }

    /// @notice Test STORAGE mode with multiple whitelisted tokens
    function test_validateTokenIn_storageMode_multipleWhitelisted() external {
        // Arrange
        PolicyConfig config = _buildConfig(FIELD_TOKEN_IN, MODE_CHECK_STORAGE);
        bytes32 id1 = _packTokenId(token1, LOCK_TAG_1);
        bytes32 id2 = _packTokenId(token2, LOCK_TAG_2);
        this.addTokenToWhitelist(CHAIN_ID_1, id1);
        this.addTokenToWhitelist(CHAIN_ID_1, id2);

        bytes32[] memory ids = new bytes32[](2);
        uint256[] memory amounts = new uint256[](2);
        ids[0] = id1;
        ids[1] = id2;
        amounts[0] = 1000;
        amounts[1] = 2000;
        bytes memory data = _encodeTokenInArray(ids, amounts);

        // Act
        (bool valid, bytes32 tokenInHash, uint256 newOffset) =
            this.validateTokenIn(data, 0, CHAIN_ID_1, config);

        // Assert
        assertTrue(valid);
        assertNotEq(tokenInHash, bytes32(0));
        assertEq(newOffset, 1 + 128); // count (1) + 2 entries (128)
    }

    /// @notice Test STORAGE mode with one whitelisted and one not
    function test_validateTokenIn_storageMode_partialWhitelist() external {
        // Arrange
        PolicyConfig config = _buildConfig(FIELD_TOKEN_IN, MODE_CHECK_STORAGE);
        bytes32 id1 = _packTokenId(token1, LOCK_TAG_1);
        bytes32 id2 = _packTokenId(token2, LOCK_TAG_2);
        this.addTokenToWhitelist(CHAIN_ID_1, id1);

        bytes32[] memory ids = new bytes32[](2);
        uint256[] memory amounts = new uint256[](2);
        ids[0] = id1;
        ids[1] = id2;
        amounts[0] = 1000;
        amounts[1] = 2000;
        bytes memory data = _encodeTokenInArray(ids, amounts);

        // Act
        (bool valid, bytes32 tokenInHash, uint256 newOffset) =
            this.validateTokenIn(data, 0, CHAIN_ID_1, config);

        // Assert
        assertFalse(valid);
        assertEq(tokenInHash, bytes32(0));
        assertEq(newOffset, 0);
    }

    /*//////////////////////////////////////////////////////////////
                           CATCHALL MODE
    //////////////////////////////////////////////////////////////*/

    /// @notice Test CATCHALL mode uses chainId 0 for lookup
    function test_validateTokenIn_catchallMode_usesChainIdZero() external {
        // Arrange
        PolicyConfig config = _buildConfig(FIELD_TOKEN_IN, MODE_CHECK_CATCHALL);
        bytes32 id = _packTokenId(token1, LOCK_TAG_1);
        this.addTokenToWhitelist(0, id);

        bytes32[] memory ids = new bytes32[](1);
        uint256[] memory amounts = new uint256[](1);
        ids[0] = id;
        amounts[0] = 1000;
        bytes memory data = _encodeTokenInArray(ids, amounts);

        // Act
        (bool valid, bytes32 tokenInHash, uint256 newOffset) =
            this.validateTokenIn(data, 0, CHAIN_ID_1, config);

        // Assert
        assertTrue(valid);
        assertNotEq(tokenInHash, bytes32(0));
        assertEq(newOffset, 1 + 64);
    }

    /// @notice Test CATCHALL mode ignores actual chainId whitelist
    function test_validateTokenIn_catchallMode_ignoresActualChainId() external {
        // Arrange
        PolicyConfig config = _buildConfig(FIELD_TOKEN_IN, MODE_CHECK_CATCHALL);
        bytes32 id = _packTokenId(token1, LOCK_TAG_1);
        this.addTokenToWhitelist(CHAIN_ID_1, id);

        bytes32[] memory ids = new bytes32[](1);
        uint256[] memory amounts = new uint256[](1);
        ids[0] = id;
        amounts[0] = 1000;
        bytes memory data = _encodeTokenInArray(ids, amounts);

        // Act
        (bool valid, bytes32 tokenInHash, uint256 newOffset) =
            this.validateTokenIn(data, 0, CHAIN_ID_1, config);

        // Assert
        assertFalse(valid);
        assertEq(tokenInHash, bytes32(0));
        assertEq(newOffset, 0);
    }

    /*//////////////////////////////////////////////////////////////
                           SUBPOLICY MODE
    //////////////////////////////////////////////////////////////*/

    /// @notice Test SUBPOLICY mode delegates to subpolicy
    function test_validateTokenIn_subpolicyMode_delegatesToSubpolicy() external {
        // Arrange
        PolicyConfig config = _buildConfig(FIELD_TOKEN_IN, MODE_CHECK_SUBPOLICY);
        this.setSubPolicy(FIELD_TOKEN_IN, address(mockSubPolicy));
        mockSubPolicy.setReturnValue(true);

        bytes32 id = _packTokenId(token1, LOCK_TAG_1);
        bytes32[] memory ids = new bytes32[](1);
        uint256[] memory amounts = new uint256[](1);
        ids[0] = id;
        amounts[0] = 1000;
        bytes memory data = _encodeTokenInArray(ids, amounts);

        // Act
        (bool valid, bytes32 tokenInHash, uint256 newOffset) =
            this.validateTokenIn(data, 0, CHAIN_ID_1, config);

        // Assert
        assertTrue(valid);
        assertNotEq(tokenInHash, bytes32(0));
        assertEq(newOffset, 1 + 64);
    }

    /// @notice Test SUBPOLICY mode returns false when subpolicy rejects
    function test_validateTokenIn_subpolicyMode_subpolicyRejects() external {
        // Arrange
        PolicyConfig config = _buildConfig(FIELD_TOKEN_IN, MODE_CHECK_SUBPOLICY);
        this.setSubPolicy(FIELD_TOKEN_IN, address(mockSubPolicy));
        mockSubPolicy.setReturnValue(false);

        bytes32 id = _packTokenId(token1, LOCK_TAG_1);
        bytes32[] memory ids = new bytes32[](1);
        uint256[] memory amounts = new uint256[](1);
        ids[0] = id;
        amounts[0] = 1000;
        bytes memory data = _encodeTokenInArray(ids, amounts);

        // Act
        (bool valid, bytes32 tokenInHash, uint256 newOffset) =
            this.validateTokenIn(data, 0, CHAIN_ID_1, config);

        // Assert
        assertFalse(valid);
        assertEq(tokenInHash, bytes32(0));
        assertEq(newOffset, 0);
    }
}
