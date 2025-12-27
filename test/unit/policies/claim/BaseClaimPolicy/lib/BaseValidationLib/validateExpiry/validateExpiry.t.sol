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

/// @title BaseValidationLib.validateExpiry Unit Tests
/// @notice Unit tests for the validateExpiry function
contract BaseValidationLib_validateExpiry_Unit_Test is BaseValidationLib_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using BaseStorageLib for ConfigId;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Result from validateExpiry
    bool internal result;

    /// @notice Mock sub-policy for SUBPOLICY mode tests
    MockSubPolicy internal mockSubPolicy;

    /// @notice Test expiry bounds
    uint128 internal minExpiry;
    uint128 internal maxExpiry;

    /// @notice Test expiry value
    uint256 internal expiry;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        super.setUp();
        mockSubPolicy = new MockSubPolicy();
        minExpiry = 1000;
        maxExpiry = 2000;
        expiry = 1500;
    }

    /*//////////////////////////////////////////////////////////////
                          EXTERNAL WRAPPER
    //////////////////////////////////////////////////////////////*/

    /// @notice External wrapper to test the library function
    function validateExpiryExternal(
        uint256 _expiry,
        PolicyConfig _config
    )
        external
        view
        returns (bool)
    {
        BasePolicyStorage storage $ = configId.getStorage({account: account, multiplexer: msg.sender});
        return BaseValidationLib.validateExpiry($, _expiry, _config, configId, account, testHash);
    }

    /*//////////////////////////////////////////////////////////////
                            MODE_SKIP TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test returns true when mode is SKIP
    function test_validateExpiry_withModeSkip() external {
        // Arrange
        config = _buildConfig(FIELD_EXPIRY, MODE_SKIP);

        // Act
        result = this.validateExpiryExternal(expiry, config);

        // Assert
        assertTrue(result);
    }

    /// @notice Test returns true when mode is SKIP regardless of expiry value
    function testFuzz_validateExpiry_withModeSkip(uint256 _expiry) external {
        // Arrange
        config = _buildConfig(FIELD_EXPIRY, MODE_SKIP);

        // Act
        result = this.validateExpiryExternal(_expiry, config);

        // Assert
        assertTrue(result);
    }

    /*//////////////////////////////////////////////////////////////
                          MODE_CHECK_STORAGE TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test returns true when expiry is within bounds
    function test_validateExpiry_withModeStorage_withinBounds() external {
        // Arrange
        config = _buildConfig(FIELD_EXPIRY, MODE_CHECK_STORAGE);
        _setupExpiry(minExpiry, maxExpiry);

        // Act
        result = this.validateExpiryExternal(1500, config);

        // Assert
        assertTrue(result);
    }

    /// @notice Test returns true when expiry equals min bound
    function test_validateExpiry_withModeStorage_equalsMinBound() external {
        // Arrange
        config = _buildConfig(FIELD_EXPIRY, MODE_CHECK_STORAGE);
        _setupExpiry(minExpiry, maxExpiry);

        // Act
        result = this.validateExpiryExternal(minExpiry, config);

        // Assert
        assertTrue(result);
    }

    /// @notice Test returns true when expiry equals max bound
    function test_validateExpiry_withModeStorage_equalsMaxBound() external {
        // Arrange
        config = _buildConfig(FIELD_EXPIRY, MODE_CHECK_STORAGE);
        _setupExpiry(minExpiry, maxExpiry);

        // Act
        result = this.validateExpiryExternal(maxExpiry, config);

        // Assert
        assertTrue(result);
    }

    /// @notice Test returns false when expiry is below min bound
    function test_validateExpiry_withModeStorage_belowMinBound() external {
        // Arrange
        config = _buildConfig(FIELD_EXPIRY, MODE_CHECK_STORAGE);
        _setupExpiry(minExpiry, maxExpiry);

        // Act
        result = this.validateExpiryExternal(minExpiry - 1, config);

        // Assert
        assertFalse(result);
    }

    /// @notice Test returns false when expiry is above max bound
    function test_validateExpiry_withModeStorage_aboveMaxBound() external {
        // Arrange
        config = _buildConfig(FIELD_EXPIRY, MODE_CHECK_STORAGE);
        _setupExpiry(minExpiry, maxExpiry);

        // Act
        result = this.validateExpiryExternal(maxExpiry + 1, config);

        // Assert
        assertFalse(result);
    }

    /// @notice Test returns false when expiry is zero and min is non-zero
    function test_validateExpiry_withModeStorage_zeroExpiry() external {
        // Arrange
        config = _buildConfig(FIELD_EXPIRY, MODE_CHECK_STORAGE);
        _setupExpiry(minExpiry, maxExpiry);

        // Act
        result = this.validateExpiryExternal(0, config);

        // Assert
        assertFalse(result);
    }

    /// @notice Test with zero bounds allows zero expiry
    function test_validateExpiry_withModeStorage_zeroBoundsZeroExpiry() external {
        // Arrange
        config = _buildConfig(FIELD_EXPIRY, MODE_CHECK_STORAGE);
        _setupExpiry(0, 0);

        // Act
        result = this.validateExpiryExternal(0, config);

        // Assert
        assertTrue(result);
    }

    /*//////////////////////////////////////////////////////////////
                          MODE_CATCHALL TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test returns true when expiry is within bounds (CATCHALL mode)
    function test_validateExpiry_withModeCatchall_withinBounds() external {
        // Arrange
        config = _buildConfig(FIELD_EXPIRY, MODE_CHECK_CATCHALL);
        _setupExpiry(minExpiry, maxExpiry);

        // Act
        result = this.validateExpiryExternal(1500, config);

        // Assert
        assertTrue(result);
    }

    /// @notice Test returns false when expiry is out of bounds (CATCHALL mode)
    function test_validateExpiry_withModeCatchall_outOfBounds() external {
        // Arrange
        config = _buildConfig(FIELD_EXPIRY, MODE_CHECK_CATCHALL);
        _setupExpiry(minExpiry, maxExpiry);

        // Act
        result = this.validateExpiryExternal(maxExpiry + 1, config);

        // Assert
        assertFalse(result);
    }

    /*//////////////////////////////////////////////////////////////
                         MODE_SUBPOLICY TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test returns true when sub-policy returns true
    function test_validateExpiry_withModeSubPolicy_subPolicyReturnsTrue() external {
        // Arrange
        config = _buildConfig(FIELD_EXPIRY, MODE_CHECK_SUBPOLICY);
        _setupSubPolicy(FIELD_EXPIRY, address(mockSubPolicy));
        mockSubPolicy.setReturnValue(true);

        // Act
        result = this.validateExpiryExternal(expiry, config);

        // Assert
        assertTrue(result);
    }

    /// @notice Test returns false when sub-policy returns false
    function test_validateExpiry_withModeSubPolicy_subPolicyReturnsFalse() external {
        // Arrange
        config = _buildConfig(FIELD_EXPIRY, MODE_CHECK_SUBPOLICY);
        _setupSubPolicy(FIELD_EXPIRY, address(mockSubPolicy));
        mockSubPolicy.setReturnValue(false);

        // Act
        result = this.validateExpiryExternal(expiry, config);

        // Assert
        assertFalse(result);
    }

    /*//////////////////////////////////////////////////////////////
                              FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test for STORAGE mode bounds checking
    function testFuzz_validateExpiry_withModeStorage(
        uint128 _min,
        uint128 _max,
        uint256 _expiry
    )
        external
    {
        // Ensure min <= max
        if (_min > _max) (_min, _max) = (_max, _min);

        // Arrange
        config = _buildConfig(FIELD_EXPIRY, MODE_CHECK_STORAGE);
        _setupExpiry(_min, _max);

        // Act
        result = this.validateExpiryExternal(_expiry, config);

        // Assert
        bool expected = _expiry >= _min && _expiry <= _max;
        assertEq(result, expected);
    }
}
