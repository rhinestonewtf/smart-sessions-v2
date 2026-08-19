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

/// @title BaseValidationLib.validateArbiter Unit Tests
/// @notice Unit tests for the validateArbiter function
contract BaseValidationLib_validateArbiter_Unit_Test is BaseValidationLib_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using BaseStorageLib for ConfigId;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Result from validateArbiter
    bool internal result;

    /// @notice Mock sub-policy for SUBPOLICY mode tests
    MockSubPolicy internal mockSubPolicy;

    /// @notice Additional test arbiters
    address internal arbiter2;
    address internal arbiter3;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        super.setUp();
        mockSubPolicy = new MockSubPolicy();
        arbiter2 = address(0xA2);
        arbiter3 = address(0xA3);
    }

    /*//////////////////////////////////////////////////////////////
                          EXTERNAL WRAPPER
    //////////////////////////////////////////////////////////////*/

    /// @notice External wrapper to test the library function
    function validateArbiterExternal(
        address _arbiter,
        PolicyConfig _config
    )
        external
        view
        returns (bool)
    {
        BasePolicyStorage storage $ =
            configId.getStorage({ account: account, multiplexer: msg.sender });
        return BaseValidationLib.validateArbiter($, _arbiter, _config, configId, account, testHash);
    }

    /*//////////////////////////////////////////////////////////////
                            MODE_SKIP TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test returns true when mode is SKIP
    function test_validateArbiter_withModeSkip() external {
        // Arrange
        config = _buildConfig(FIELD_ARBITER, MODE_SKIP);

        // Act
        result = this.validateArbiterExternal(arbiter, config);

        // Assert
        assertTrue(result);
    }

    /// @notice Test returns true when mode is SKIP even with random arbiter
    function testFuzz_validateArbiter_withModeSkip(address _arbiter) external {
        // Arrange
        config = _buildConfig(FIELD_ARBITER, MODE_SKIP);

        // Act
        result = this.validateArbiterExternal(_arbiter, config);

        // Assert
        assertTrue(result);
    }

    /*//////////////////////////////////////////////////////////////
                          MODE_CHECK_STORAGE TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test returns true when arbiter is in whitelist (STORAGE mode)
    function test_validateArbiter_withModeStorage_arbiterInWhitelist() external {
        // Arrange
        config = _buildConfig(FIELD_ARBITER, MODE_CHECK_STORAGE);
        _setupArbiter(arbiter);

        // Act
        result = this.validateArbiterExternal(arbiter, config);

        // Assert
        assertTrue(result);
    }

    /// @notice Test returns false when arbiter is not in whitelist (STORAGE mode)
    function test_validateArbiter_withModeStorage_arbiterNotInWhitelist() external {
        // Arrange
        config = _buildConfig(FIELD_ARBITER, MODE_CHECK_STORAGE);
        _setupArbiter(arbiter2); // Different arbiter in whitelist

        // Act
        result = this.validateArbiterExternal(arbiter, config);

        // Assert
        assertFalse(result);
    }

    /// @notice Test returns false when whitelist is empty (STORAGE mode)
    function test_validateArbiter_withModeStorage_emptyWhitelist() external {
        // Arrange
        config = _buildConfig(FIELD_ARBITER, MODE_CHECK_STORAGE);
        // No arbiters added to whitelist

        // Act
        result = this.validateArbiterExternal(arbiter, config);

        // Assert
        assertFalse(result);
    }

    /// @notice Test works with multiple arbiters in whitelist
    function test_validateArbiter_withModeStorage_multipleArbitersInWhitelist() external {
        // Arrange
        config = _buildConfig(FIELD_ARBITER, MODE_CHECK_STORAGE);
        address[] memory arbiters = new address[](3);
        arbiters[0] = arbiter;
        arbiters[1] = arbiter2;
        arbiters[2] = arbiter3;
        _setupArbiters(arbiters);

        // Act & Assert - all should pass
        assertTrue(this.validateArbiterExternal(arbiter, config));
        assertTrue(this.validateArbiterExternal(arbiter2, config));
        assertTrue(this.validateArbiterExternal(arbiter3, config));

        // Unknown arbiter should fail
        assertFalse(this.validateArbiterExternal(address(0xDEAD), config));
    }

    /*//////////////////////////////////////////////////////////////
                          MODE_CATCHALL TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test returns true when arbiter is in whitelist (CATCHALL mode)
    function test_validateArbiter_withModeCatchall_arbiterInWhitelist() external {
        // Arrange
        config = _buildConfig(FIELD_ARBITER, MODE_CHECK_CATCHALL);
        _setupArbiter(arbiter);

        // Act
        result = this.validateArbiterExternal(arbiter, config);

        // Assert
        assertTrue(result);
    }

    /// @notice Test returns false when arbiter is not in whitelist (CATCHALL mode)
    function test_validateArbiter_withModeCatchall_arbiterNotInWhitelist() external {
        // Arrange
        config = _buildConfig(FIELD_ARBITER, MODE_CHECK_CATCHALL);
        _setupArbiter(arbiter2);

        // Act
        result = this.validateArbiterExternal(arbiter, config);

        // Assert
        assertFalse(result);
    }

    /*//////////////////////////////////////////////////////////////
                         MODE_SUBPOLICY TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test returns true when sub-policy returns true
    function test_validateArbiter_withModeSubPolicy_subPolicyReturnsTrue() external {
        // Arrange
        config = _buildConfig(FIELD_ARBITER, MODE_CHECK_SUBPOLICY);
        _setupSubPolicy(FIELD_ARBITER, address(mockSubPolicy));
        mockSubPolicy.setReturnValue(true);

        // Act
        result = this.validateArbiterExternal(arbiter, config);

        // Assert
        assertTrue(result);
    }

    /// @notice Test returns false when sub-policy returns false
    function test_validateArbiter_withModeSubPolicy_subPolicyReturnsFalse() external {
        // Arrange
        config = _buildConfig(FIELD_ARBITER, MODE_CHECK_SUBPOLICY);
        _setupSubPolicy(FIELD_ARBITER, address(mockSubPolicy));
        mockSubPolicy.setReturnValue(false);

        // Act
        result = this.validateArbiterExternal(arbiter, config);

        // Assert
        assertFalse(result);
    }

    /*//////////////////////////////////////////////////////////////
                              FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test for STORAGE mode
    function testFuzz_validateArbiter_withModeStorage(
        address _arbiter,
        address _whitelistedArbiter
    )
        external
    {
        // Arrange
        config = _buildConfig(FIELD_ARBITER, MODE_CHECK_STORAGE);
        _setupArbiter(_whitelistedArbiter);

        // Act
        result = this.validateArbiterExternal(_arbiter, config);

        // Assert
        assertEq(result, _arbiter == _whitelistedArbiter);
    }
}
