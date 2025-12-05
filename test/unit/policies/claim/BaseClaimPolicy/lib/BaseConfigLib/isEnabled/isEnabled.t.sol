// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { BaseConfigLib_Unit_Test } from "../BaseConfigLib.t.sol";

// Libraries
import { BaseConfigLib, PolicyConfig } from "@policies/claim/base/lib/BaseConfigLib.sol";

/// @title BaseConfigLib.isEnabled Unit Tests
/// @notice Unit tests for the isEnabled function
contract BaseConfigLib_isEnabled_Unit_Test is BaseConfigLib_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using BaseConfigLib for PolicyConfig;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Result from isEnabled
    bool internal result;

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test returns false when mode is SKIP
    function test_isEnabled_withModeSkip() external {
        // Arrange - ARBITER bits 0-1 = 00
        config = PolicyConfig.wrap(0x00000000);

        // Act
        result = config.isEnabled(FIELD_ARBITER);

        // Assert
        assertEq(result, false);
    }

    /// @notice Test returns true when mode is STORAGE
    function test_isEnabled_withModeStorage() external {
        // Arrange - ARBITER bits 0-1 = 01
        config = PolicyConfig.wrap(0x00000001);

        // Act
        result = config.isEnabled(FIELD_ARBITER);

        // Assert
        assertEq(result, true);
    }

    /// @notice Test returns true when mode is CATCHALL
    function test_isEnabled_withModeCatchall() external {
        // Arrange - ARBITER bits 0-1 = 10
        config = PolicyConfig.wrap(0x00000002);

        // Act
        result = config.isEnabled(FIELD_ARBITER);

        // Assert
        assertEq(result, true);
    }

    /// @notice Test returns true when mode is SUBPOLICY
    function test_isEnabled_withModeSubpolicy() external {
        // Arrange - ARBITER bits 0-1 = 11
        config = PolicyConfig.wrap(0x00000003);

        // Act
        result = config.isEnabled(FIELD_ARBITER);

        // Assert
        assertEq(result, true);
    }

    /// @notice Fuzz test for isEnabled across all fields
    function testFuzz_isEnabled(uint32 _modeConfig, uint8 _fieldId) external {
        // Bound field ID to valid range
        _fieldId = uint8(bound(_fieldId, 0, 9));

        // Arrange
        config = PolicyConfig.wrap(_modeConfig);

        // Act
        result = config.isEnabled(_fieldId);

        // Assert - enabled if mode != 0
        uint8 fieldMode = uint8((_modeConfig >> (_fieldId * 2)) & 0x3);
        assertEq(result, fieldMode != 0);
    }
}
