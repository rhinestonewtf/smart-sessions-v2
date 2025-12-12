// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { BaseValidationLib_Unit_Test } from "../BaseValidationLib.t.sol";

// Libraries
import { BaseValidationLib } from "@policies/claim/base/lib/BaseValidationLib.sol";
import { BaseStorageLib, BasePolicyStorage } from "@policies/claim/base/lib/BaseStorageLib.sol";
import { PolicyConfig } from "@policies/claim/base/lib/BaseConfigLib.sol";

// Mocks
import { MockSubPolicy } from "@mocks/MockSubPolicy.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";

/// @title BaseValidationLib.validateTokenOut Unit Tests
/// @notice Unit tests for the validateTokenOut function
contract BaseValidationLib_validateTokenOut_Unit_Test is BaseValidationLib_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using BaseStorageLib for ConfigId;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Results from validateTokenOut
    bool internal valid;
    bytes32 internal tokenOutHash;
    uint256 internal newOffset;

    /// @notice Mock sub-policy for SUBPOLICY mode tests
    MockSubPolicy internal mockSubPolicy;

    /// @notice Test token amounts
    uint256 internal amount1;
    uint256 internal amount2;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        super.setUp();
        mockSubPolicy = new MockSubPolicy();
        amount1 = 1000 ether;
        amount2 = 2000 ether;
    }

    /*//////////////////////////////////////////////////////////////
                          EXTERNAL WRAPPER
    //////////////////////////////////////////////////////////////*/

    /// @notice External wrapper to test the library function
    function validateTokenOutExternal(
        bytes calldata _data,
        uint256 _offset,
        uint256 _targetChainId,
        PolicyConfig _config
    )
        external
        view
        returns (bool, bytes32, uint256)
    {
        BasePolicyStorage storage $ = configId.getStorage(account);
        return BaseValidationLib.validateTokenOut(
            $, _data, _offset, _targetChainId, _config, configId, account, testHash
        );
    }

    /*//////////////////////////////////////////////////////////////
                              HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Builds tokenOut calldata with single token
    /// @param _token Token address
    /// @param _amount Token amount
    /// @return Encoded calldata: [length: 1][token: 32][amount: 32]
    function _buildSingleTokenData(
        address _token,
        uint256 _amount
    )
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            uint8(1), // length
            uint256(uint160(_token)), // token (left-padded to 32 bytes)
            _amount // amount
        );
    }

    /// @notice Builds tokenOut calldata with two tokens
    function _buildTwoTokenData(
        address _token1,
        uint256 _amount1,
        address _token2,
        uint256 _amount2
    )
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            uint8(2), // length
            uint256(uint160(_token1)),
            _amount1,
            uint256(uint160(_token2)),
            _amount2
        );
    }

    /// @notice Builds empty tokenOut calldata
    function _buildEmptyTokenData() internal pure returns (bytes memory) {
        return abi.encodePacked(uint8(0));
    }

    /*//////////////////////////////////////////////////////////////
                          MODE_CHECK_STORAGE TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test returns valid=true when single token is in whitelist
    function test_validateTokenOut_withModeStorage_singleTokenInWhitelist() external {
        // Arrange
        config = _buildConfig(FIELD_TOKEN_OUT, MODE_CHECK_STORAGE);
        _setupTokenOut(targetChainId, token1);
        data = _buildSingleTokenData(token1, amount1);

        // Act
        (valid, tokenOutHash, newOffset) =
            this.validateTokenOutExternal(data, 0, targetChainId, config);

        // Assert
        assertTrue(valid);
        assertNotEq(tokenOutHash, bytes32(0));
        assertEq(newOffset, data.length);
    }

    /// @notice Test returns valid=true when all tokens are in whitelist
    function test_validateTokenOut_withModeStorage_allTokensInWhitelist() external {
        // Arrange
        config = _buildConfig(FIELD_TOKEN_OUT, MODE_CHECK_STORAGE);
        _setupTokenOut(targetChainId, token1);
        _setupTokenOut(targetChainId, token2);
        data = _buildTwoTokenData(token1, amount1, token2, amount2);

        // Act
        (valid, tokenOutHash, newOffset) =
            this.validateTokenOutExternal(data, 0, targetChainId, config);

        // Assert
        assertTrue(valid);
        assertNotEq(tokenOutHash, bytes32(0));
        assertEq(newOffset, data.length);
    }

    /// @notice Test returns valid=false when one token is not in whitelist
    function test_validateTokenOut_withModeStorage_oneTokenNotInWhitelist() external {
        // Arrange
        config = _buildConfig(FIELD_TOKEN_OUT, MODE_CHECK_STORAGE);
        _setupTokenOut(targetChainId, token1); // Only token1 whitelisted
        data = _buildTwoTokenData(token1, amount1, token2, amount2); // But data has token2

        // Act
        (valid, tokenOutHash, newOffset) =
            this.validateTokenOutExternal(data, 0, targetChainId, config);

        // Assert
        assertFalse(valid);
        assertEq(tokenOutHash, bytes32(0));
        assertEq(newOffset, 0);
    }

    /// @notice Test returns valid=false when whitelist is empty
    function test_validateTokenOut_withModeStorage_emptyWhitelist() external {
        // Arrange
        config = _buildConfig(FIELD_TOKEN_OUT, MODE_CHECK_STORAGE);
        // No tokens added to whitelist
        data = _buildSingleTokenData(token1, amount1);

        // Act
        (valid, tokenOutHash, newOffset) =
            this.validateTokenOutExternal(data, 0, targetChainId, config);

        // Assert
        assertFalse(valid);
        assertEq(tokenOutHash, bytes32(0));
        assertEq(newOffset, 0);
    }

    /// @notice Test handles empty token array
    function test_validateTokenOut_withModeStorage_emptyTokenArray() external {
        // Arrange
        config = _buildConfig(FIELD_TOKEN_OUT, MODE_CHECK_STORAGE);
        _setupTokenOut(targetChainId, token1); // Whitelist not empty
        data = _buildEmptyTokenData();

        // Act
        (valid, tokenOutHash, newOffset) =
            this.validateTokenOutExternal(data, 0, targetChainId, config);

        // Assert
        assertTrue(valid);
        assertEq(newOffset, 1); // Just the length byte
    }

    /// @notice Test with non-zero offset
    function test_validateTokenOut_withModeStorage_nonZeroOffset() external {
        // Arrange
        config = _buildConfig(FIELD_TOKEN_OUT, MODE_CHECK_STORAGE);
        _setupTokenOut(targetChainId, token1);

        // Prepend some garbage data
        bytes memory tokenData = _buildSingleTokenData(token1, amount1);
        data = abi.encodePacked(bytes32(bytes20(address(0xDEAD))), tokenData);

        // Act - start at offset 32
        (valid, tokenOutHash, newOffset) =
            this.validateTokenOutExternal(data, 32, targetChainId, config);

        // Assert
        assertTrue(valid);
        assertEq(newOffset, 32 + tokenData.length);
    }

    /// @notice Test different chain IDs have separate whitelists
    function test_validateTokenOut_withModeStorage_differentChainIds() external {
        // Arrange
        config = _buildConfig(FIELD_TOKEN_OUT, MODE_CHECK_STORAGE);
        _setupTokenOut(1, token1);
        _setupTokenOut(137, token2);

        bytes memory token1Data = _buildSingleTokenData(token1, amount1);
        bytes memory token2Data = _buildSingleTokenData(token2, amount2);

        // Act & Assert - token1 valid on chain 1 only
        (valid,,) = this.validateTokenOutExternal(token1Data, 0, 1, config);
        assertTrue(valid);
        (valid,,) = this.validateTokenOutExternal(token1Data, 0, 137, config);
        assertFalse(valid);

        // token2 valid on chain 137 only
        (valid,,) = this.validateTokenOutExternal(token2Data, 0, 137, config);
        assertTrue(valid);
        (valid,,) = this.validateTokenOutExternal(token2Data, 0, 1, config);
        assertFalse(valid);
    }

    /// @notice Test returns valid=false when whitelist is empty even with empty token array
    function test_validateTokenOut_withModeStorage_emptyWhitelistEmptyTokenArray() external {
        // Arrange
        config = _buildConfig(FIELD_TOKEN_OUT, MODE_CHECK_STORAGE);
        // No tokens added to whitelist
        data = _buildEmptyTokenData(); // empty token array

        // Act
        (valid, tokenOutHash, newOffset) =
            this.validateTokenOutExternal(data, 0, targetChainId, config);

        // Assert - should still fail because whitelist is empty
        assertFalse(valid);
    }

    /*//////////////////////////////////////////////////////////////
                          MODE_CATCHALL TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test CATCHALL mode uses chainId 0 for lookup
    function test_validateTokenOut_withModeCatchall_usesChainIdZero() external {
        // Arrange
        config = _buildConfig(FIELD_TOKEN_OUT, MODE_CHECK_CATCHALL);
        _setupTokenOut(0, token1); // Store at chainId 0 (catch-all)
        data = _buildSingleTokenData(token1, amount1);

        // Act - should use chainId 0 regardless of passed chainId
        (valid, tokenOutHash, newOffset) = this.validateTokenOutExternal(data, 0, 137, config);

        // Assert
        assertTrue(valid);
    }

    /// @notice Test CATCHALL ignores chain-specific config
    function test_validateTokenOut_withModeCatchall_ignoresChainSpecificConfig() external {
        // Arrange
        config = _buildConfig(FIELD_TOKEN_OUT, MODE_CHECK_CATCHALL);
        _setupTokenOut(targetChainId, token1); // Store at specific chainId
        // Don't set up catch-all (chainId 0)
        data = _buildSingleTokenData(token1, amount1);

        // Act
        (valid,,) = this.validateTokenOutExternal(data, 0, targetChainId, config);

        // Assert - should fail because catch-all whitelist is empty
        assertFalse(valid);
    }

    /*//////////////////////////////////////////////////////////////
                         MODE_SUBPOLICY TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test returns valid=true when sub-policy returns true
    function test_validateTokenOut_withModeSubPolicy_subPolicyReturnsTrue() external {
        // Arrange
        config = _buildConfig(FIELD_TOKEN_OUT, MODE_CHECK_SUBPOLICY);
        _setupSubPolicy(FIELD_TOKEN_OUT, address(mockSubPolicy));
        mockSubPolicy.setReturnValue(true);
        data = _buildSingleTokenData(token1, amount1);

        // Act
        (valid, tokenOutHash, newOffset) =
            this.validateTokenOutExternal(data, 0, targetChainId, config);

        // Assert
        assertTrue(valid);
        assertNotEq(tokenOutHash, bytes32(0));
    }

    /// @notice Test returns valid=false when sub-policy returns false
    function test_validateTokenOut_withModeSubPolicy_subPolicyReturnsFalse() external {
        // Arrange
        config = _buildConfig(FIELD_TOKEN_OUT, MODE_CHECK_SUBPOLICY);
        _setupSubPolicy(FIELD_TOKEN_OUT, address(mockSubPolicy));
        mockSubPolicy.setReturnValue(false);
        data = _buildSingleTokenData(token1, amount1);

        // Act
        (valid, tokenOutHash, newOffset) =
            this.validateTokenOutExternal(data, 0, targetChainId, config);

        // Assert
        assertFalse(valid);
        assertEq(tokenOutHash, bytes32(0));
    }
}
