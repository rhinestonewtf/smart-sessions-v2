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

/// @title BaseValidationLib.validateFillExpiry Unit Tests
/// @notice Unit tests for the validateFillExpiry function
contract BaseValidationLib_validateFillExpiry_Unit_Test is BaseValidationLib_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using BaseStorageLib for ConfigId;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Result from validateFillExpiry
    bool internal result;

    /// @notice Mock sub-policy for SUBPOLICY mode tests
    MockSubPolicy internal mockSubPolicy;

    /// @notice Test fill expiry bounds
    uint128 internal minFillExpiry;
    uint128 internal maxFillExpiry;

    /// @notice Test fill expiry value
    uint256 internal fillExpiry;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        super.setUp();
        mockSubPolicy = new MockSubPolicy();
        minFillExpiry = 1000;
        maxFillExpiry = 2000;
        fillExpiry = 1500;
    }

    /*//////////////////////////////////////////////////////////////
                          EXTERNAL WRAPPER
    //////////////////////////////////////////////////////////////*/

    /// @notice External wrapper to test the library function
    function validateFillExpiryExternal(
        uint256 _fillExpiry,
        uint256 _targetChainId,
        PolicyConfig _config
    )
        external
        view
        returns (bool)
    {
        BasePolicyStorage storage $ = configId.getStorage({account: account, multiplexor: msg.sender});
        return BaseValidationLib.validateFillExpiry(
            $, _fillExpiry, _targetChainId, _config, configId, account, testHash
        );
    }

    /*//////////////////////////////////////////////////////////////
                            MODE_SKIP TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test returns true when mode is SKIP
    function test_validateFillExpiry_withModeSkip() external {
        // Arrange
        config = _buildConfig(FIELD_FILL_EXPIRY, MODE_SKIP);

        // Act
        result = this.validateFillExpiryExternal(fillExpiry, targetChainId, config);

        // Assert
        assertTrue(result);
    }

    /// @notice Test returns true when mode is SKIP regardless of fillExpiry value
    function testFuzz_validateFillExpiry_withModeSkip(
        uint256 _fillExpiry,
        uint256 _chainId
    )
        external
    {
        // Arrange
        config = _buildConfig(FIELD_FILL_EXPIRY, MODE_SKIP);

        // Act
        result = this.validateFillExpiryExternal(_fillExpiry, _chainId, config);

        // Assert
        assertTrue(result);
    }

    /*//////////////////////////////////////////////////////////////
                          MODE_CHECK_STORAGE TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test returns true when fillExpiry is within bounds
    function test_validateFillExpiry_withModeStorage_withinBounds() external {
        // Arrange
        config = _buildConfig(FIELD_FILL_EXPIRY, MODE_CHECK_STORAGE);
        _setupFillExpiry(targetChainId, minFillExpiry, maxFillExpiry);

        // Act
        result = this.validateFillExpiryExternal(1500, targetChainId, config);

        // Assert
        assertTrue(result);
    }

    /// @notice Test returns true when fillExpiry equals min bound
    function test_validateFillExpiry_withModeStorage_equalsMinBound() external {
        // Arrange
        config = _buildConfig(FIELD_FILL_EXPIRY, MODE_CHECK_STORAGE);
        _setupFillExpiry(targetChainId, minFillExpiry, maxFillExpiry);

        // Act
        result = this.validateFillExpiryExternal(minFillExpiry, targetChainId, config);

        // Assert
        assertTrue(result);
    }

    /// @notice Test returns true when fillExpiry equals max bound
    function test_validateFillExpiry_withModeStorage_equalsMaxBound() external {
        // Arrange
        config = _buildConfig(FIELD_FILL_EXPIRY, MODE_CHECK_STORAGE);
        _setupFillExpiry(targetChainId, minFillExpiry, maxFillExpiry);

        // Act
        result = this.validateFillExpiryExternal(maxFillExpiry, targetChainId, config);

        // Assert
        assertTrue(result);
    }

    /// @notice Test returns false when fillExpiry is below min bound
    function test_validateFillExpiry_withModeStorage_belowMinBound() external {
        // Arrange
        config = _buildConfig(FIELD_FILL_EXPIRY, MODE_CHECK_STORAGE);
        _setupFillExpiry(targetChainId, minFillExpiry, maxFillExpiry);

        // Act
        result = this.validateFillExpiryExternal(minFillExpiry - 1, targetChainId, config);

        // Assert
        assertFalse(result);
    }

    /// @notice Test returns false when fillExpiry is above max bound
    function test_validateFillExpiry_withModeStorage_aboveMaxBound() external {
        // Arrange
        config = _buildConfig(FIELD_FILL_EXPIRY, MODE_CHECK_STORAGE);
        _setupFillExpiry(targetChainId, minFillExpiry, maxFillExpiry);

        // Act
        result = this.validateFillExpiryExternal(maxFillExpiry + 1, targetChainId, config);

        // Assert
        assertFalse(result);
    }

    /// @notice Test different chain IDs have separate bounds
    function test_validateFillExpiry_withModeStorage_differentChainIds() external {
        // Arrange
        config = _buildConfig(FIELD_FILL_EXPIRY, MODE_CHECK_STORAGE);
        _setupFillExpiry(1, 100, 200);
        _setupFillExpiry(137, 1000, 2000);

        // Act & Assert
        assertTrue(this.validateFillExpiryExternal(150, 1, config));
        assertFalse(this.validateFillExpiryExternal(150, 137, config)); // Out of bounds for chain
        // 137
        assertTrue(this.validateFillExpiryExternal(1500, 137, config));
        assertFalse(this.validateFillExpiryExternal(1500, 1, config)); // Out of bounds for chain 1
    }

    /*//////////////////////////////////////////////////////////////
                          MODE_CATCHALL TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test CATCHALL mode uses chainId 0 for lookup
    function test_validateFillExpiry_withModeCatchall_usesChainIdZero() external {
        // Arrange
        config = _buildConfig(FIELD_FILL_EXPIRY, MODE_CHECK_CATCHALL);
        _setupFillExpiry(0, minFillExpiry, maxFillExpiry); // Store at chainId 0 (catch-all)

        // Act - should use chainId 0 regardless of passed chainId
        result = this.validateFillExpiryExternal(1500, 137, config);

        // Assert
        assertTrue(result);
    }

    /// @notice Test CATCHALL ignores chain-specific config
    function test_validateFillExpiry_withModeCatchall_ignoresChainSpecificConfig() external {
        // Arrange
        config = _buildConfig(FIELD_FILL_EXPIRY, MODE_CHECK_CATCHALL);
        _setupFillExpiry(targetChainId, minFillExpiry, maxFillExpiry); // Store at specific chainId
        // Don't set up catch-all (chainId 0)

        // Act
        result = this.validateFillExpiryExternal(1500, targetChainId, config);

        // Assert - should fail because catch-all bounds are 0,0 and 1500 is out of range
        assertFalse(result);
    }

    /// @notice Test CATCHALL works across multiple chains
    function test_validateFillExpiry_withModeCatchall_worksAcrossChains() external {
        // Arrange
        config = _buildConfig(FIELD_FILL_EXPIRY, MODE_CHECK_CATCHALL);
        _setupFillExpiry(0, minFillExpiry, maxFillExpiry);

        // Act & Assert - same bounds apply to all chains
        assertTrue(this.validateFillExpiryExternal(1500, 1, config));
        assertTrue(this.validateFillExpiryExternal(1500, 137, config));
        assertTrue(this.validateFillExpiryExternal(1500, 42_161, config));
    }

    /*//////////////////////////////////////////////////////////////
                         MODE_SUBPOLICY TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test returns true when sub-policy returns true
    function test_validateFillExpiry_withModeSubPolicy_subPolicyReturnsTrue() external {
        // Arrange
        config = _buildConfig(FIELD_FILL_EXPIRY, MODE_CHECK_SUBPOLICY);
        _setupSubPolicy(FIELD_FILL_EXPIRY, address(mockSubPolicy));
        mockSubPolicy.setReturnValue(true);

        // Act
        result = this.validateFillExpiryExternal(fillExpiry, targetChainId, config);

        // Assert
        assertTrue(result);
    }

    /// @notice Test returns false when sub-policy returns false
    function test_validateFillExpiry_withModeSubPolicy_subPolicyReturnsFalse() external {
        // Arrange
        config = _buildConfig(FIELD_FILL_EXPIRY, MODE_CHECK_SUBPOLICY);
        _setupSubPolicy(FIELD_FILL_EXPIRY, address(mockSubPolicy));
        mockSubPolicy.setReturnValue(false);

        // Act
        result = this.validateFillExpiryExternal(fillExpiry, targetChainId, config);

        // Assert
        assertFalse(result);
    }

    /*//////////////////////////////////////////////////////////////
                              FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test for STORAGE mode bounds checking
    function testFuzz_validateFillExpiry_withModeStorage(
        uint128 _min,
        uint128 _max,
        uint256 _fillExpiry,
        uint256 _chainId
    )
        external
    {
        // Ensure min <= max
        if (_min > _max) (_min, _max) = (_max, _min);

        // Arrange
        config = _buildConfig(FIELD_FILL_EXPIRY, MODE_CHECK_STORAGE);
        _setupFillExpiry(_chainId, _min, _max);

        // Act
        result = this.validateFillExpiryExternal(_fillExpiry, _chainId, config);

        // Assert
        bool expected = _fillExpiry >= _min && _fillExpiry <= _max;
        assertEq(result, expected);
    }
}
