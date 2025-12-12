// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import { Permit2ValidationLib_Unit_Test } from "../Permit2ValidationLib.t.sol";

// Types
import {
    PolicyConfig,
    MODE_SKIP,
    MODE_CHECK_STORAGE,
    MODE_CHECK_CATCHALL,
    MODE_CHECK_SUBPOLICY,
    FIELD_TOKEN_IN
} from "@policies/claim/base/types/BaseDataTypes.sol";

/// @title Permit2ValidationLib.validateTokenIn Unit Tests
/// @notice Unit tests for the validateTokenIn function
contract Permit2ValidationLib_validateTokenIn_Unit_Test is Permit2ValidationLib_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                              SKIP MODE
    //////////////////////////////////////////////////////////////*/

    /// @notice Test SKIP mode returns pre-computed hash
    function test_validateTokenIn_skipMode_returnsHash() external {
        // Arrange
        PolicyConfig config = _buildConfig(FIELD_TOKEN_IN, MODE_SKIP);
        bytes32 precomputedHash = keccak256("tokenInHash");
        bytes memory data = _encodeTokenInHash(precomputedHash);

        // Act
        (bool valid, bytes32 tokenInHash, uint256 newOffset) = this.validateTokenIn(data, 0, config);

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
        this.addTokenToWhitelist(block.chainid, token1);

        address[] memory tokens = new address[](1);
        uint256[] memory amounts = new uint256[](1);
        tokens[0] = token1;
        amounts[0] = 1000;
        bytes memory data = _encodeTokenInArray(tokens, amounts);

        // Act
        (bool valid, bytes32 tokenInHash, uint256 newOffset) = this.validateTokenIn(data, 0, config);

        // Assert
        assertTrue(valid);
        assertNotEq(tokenInHash, bytes32(0));
        assertEq(newOffset, 1 + 64); // count (1) + 1 entry (64)
    }

    /// @notice Test STORAGE mode with non-whitelisted token
    function test_validateTokenIn_storageMode_notWhitelisted() external {
        // Arrange
        PolicyConfig config = _buildConfig(FIELD_TOKEN_IN, MODE_CHECK_STORAGE);
        this.addTokenToWhitelist(block.chainid, token1);

        address[] memory tokens = new address[](1);
        uint256[] memory amounts = new uint256[](1);
        tokens[0] = token2; // not whitelisted
        amounts[0] = 1000;
        bytes memory data = _encodeTokenInArray(tokens, amounts);

        // Act
        (bool valid, bytes32 tokenInHash, uint256 newOffset) = this.validateTokenIn(data, 0, config);

        // Assert
        assertFalse(valid);
        assertEq(tokenInHash, bytes32(0));
        assertEq(newOffset, 0);
    }

    /// @notice Test STORAGE mode with empty whitelist
    function test_validateTokenIn_storageMode_emptyWhitelist() external {
        // Arrange
        PolicyConfig config = _buildConfig(FIELD_TOKEN_IN, MODE_CHECK_STORAGE);

        address[] memory tokens = new address[](1);
        uint256[] memory amounts = new uint256[](1);
        tokens[0] = token1;
        amounts[0] = 1000;
        bytes memory data = _encodeTokenInArray(tokens, amounts);

        // Act
        (bool valid, bytes32 tokenInHash, uint256 newOffset) = this.validateTokenIn(data, 0, config);

        // Assert
        assertFalse(valid);
        assertEq(tokenInHash, bytes32(0));
        assertEq(newOffset, 0);
    }

    /// @notice Test STORAGE mode with multiple whitelisted tokens
    function test_validateTokenIn_storageMode_multipleWhitelisted() external {
        // Arrange
        PolicyConfig config = _buildConfig(FIELD_TOKEN_IN, MODE_CHECK_STORAGE);
        this.addTokenToWhitelist(block.chainid, token1);
        this.addTokenToWhitelist(block.chainid, token2);

        address[] memory tokens = new address[](2);
        uint256[] memory amounts = new uint256[](2);
        tokens[0] = token1;
        tokens[1] = token2;
        amounts[0] = 1000;
        amounts[1] = 2000;
        bytes memory data = _encodeTokenInArray(tokens, amounts);

        // Act
        (bool valid, bytes32 tokenInHash, uint256 newOffset) = this.validateTokenIn(data, 0, config);

        // Assert
        assertTrue(valid);
        assertNotEq(tokenInHash, bytes32(0));
        assertEq(newOffset, 1 + 128); // count (1) + 2 entries (128)
    }

    /// @notice Test STORAGE mode with one whitelisted and one not
    function test_validateTokenIn_storageMode_partialWhitelist() external {
        // Arrange
        PolicyConfig config = _buildConfig(FIELD_TOKEN_IN, MODE_CHECK_STORAGE);
        this.addTokenToWhitelist(block.chainid, token1);

        address[] memory tokens = new address[](2);
        uint256[] memory amounts = new uint256[](2);
        tokens[0] = token1;
        tokens[1] = token2; // not whitelisted
        amounts[0] = 1000;
        amounts[1] = 2000;
        bytes memory data = _encodeTokenInArray(tokens, amounts);

        // Act
        (bool valid, bytes32 tokenInHash, uint256 newOffset) = this.validateTokenIn(data, 0, config);

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
        this.addTokenToWhitelist(0, token1);

        address[] memory tokens = new address[](1);
        uint256[] memory amounts = new uint256[](1);
        tokens[0] = token1;
        amounts[0] = 1000;
        bytes memory data = _encodeTokenInArray(tokens, amounts);

        // Act
        (bool valid, bytes32 tokenInHash, uint256 newOffset) = this.validateTokenIn(data, 0, config);

        // Assert
        assertTrue(valid);
        assertNotEq(tokenInHash, bytes32(0));
        assertEq(newOffset, 1 + 64);
    }

    /// @notice Test CATCHALL mode ignores actual chainId whitelist
    function test_validateTokenIn_catchallMode_ignoresActualChainId() external {
        // Arrange
        PolicyConfig config = _buildConfig(FIELD_TOKEN_IN, MODE_CHECK_CATCHALL);
        this.addTokenToWhitelist(block.chainid, token1);

        address[] memory tokens = new address[](1);
        uint256[] memory amounts = new uint256[](1);
        tokens[0] = token1;
        amounts[0] = 1000;
        bytes memory data = _encodeTokenInArray(tokens, amounts);

        // Act
        (bool valid, bytes32 tokenInHash, uint256 newOffset) = this.validateTokenIn(data, 0, config);

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

        address[] memory tokens = new address[](1);
        uint256[] memory amounts = new uint256[](1);
        tokens[0] = token1;
        amounts[0] = 1000;
        bytes memory data = _encodeTokenInArray(tokens, amounts);

        // Act
        (bool valid, bytes32 tokenInHash, uint256 newOffset) = this.validateTokenIn(data, 0, config);

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

        address[] memory tokens = new address[](1);
        uint256[] memory amounts = new uint256[](1);
        tokens[0] = token1;
        amounts[0] = 1000;
        bytes memory data = _encodeTokenInArray(tokens, amounts);

        // Act
        (bool valid, bytes32 tokenInHash, uint256 newOffset) = this.validateTokenIn(data, 0, config);

        // Assert
        assertFalse(valid);
        assertEq(tokenInHash, bytes32(0));
        assertEq(newOffset, 0);
    }
}

