// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { BaseConfigLib_Unit_Test } from "../BaseConfigLib.t.sol";

// Libraries
import { BaseConfigLib, PolicyConfig } from "@policies/claim/base/lib/BaseConfigLib.sol";

/// @title BaseConfigLib.getFieldMode Unit Tests
/// @notice Unit tests for the getFieldMode function
contract BaseConfigLib_getFieldMode_Unit_Test is BaseConfigLib_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using BaseConfigLib for PolicyConfig;

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test extracting SKIP mode for ARBITER field
    function test_getFieldMode_withArbiterSkip() external {
        // Arrange - all zeros = all SKIP
        config = PolicyConfig.wrap(0x00000000);

        // Act
        mode = config.getFieldMode(FIELD_ARBITER);

        // Assert
        assertEq(mode, MODE_SKIP);
    }

    /// @notice Test extracting STORAGE mode for ARBITER field
    function test_getFieldMode_withArbiterStorage() external {
        // Arrange - 0b01 in bits 0-1
        config = PolicyConfig.wrap(0x00000001);

        // Act
        mode = config.getFieldMode(FIELD_ARBITER);

        // Assert
        assertEq(mode, MODE_CHECK_STORAGE);
    }

    /// @notice Test extracting CATCHALL mode for ARBITER field
    function test_getFieldMode_withArbiterCatchall() external {
        // Arrange - 0b10 in bits 0-1
        config = PolicyConfig.wrap(0x00000002);

        // Act
        mode = config.getFieldMode(FIELD_ARBITER);

        // Assert
        assertEq(mode, MODE_CHECK_CATCHALL);
    }

    /// @notice Test extracting SUBPOLICY mode for ARBITER field
    function test_getFieldMode_withArbiterSubpolicy() external {
        // Arrange - 0b11 in bits 0-1
        config = PolicyConfig.wrap(0x00000003);

        // Act
        mode = config.getFieldMode(FIELD_ARBITER);

        // Assert
        assertEq(mode, MODE_CHECK_SUBPOLICY);
    }

    /// @notice Test extracting mode for RECIPIENT field (id 3, bits 6-7)
    function test_getFieldMode_withRecipientInMiddle() external {
        // Arrange - 0b10 in bits 6-7 = 0x80 (128 in decimal, 0b10000000)
        config = PolicyConfig.wrap(0x00000080);

        // Act
        mode = config.getFieldMode(FIELD_RECIPIENT);

        // Assert
        assertEq(mode, MODE_CHECK_CATCHALL);
    }

    /// @notice Test extracting mode for RECIPIENT_IS_SPONSOR field (id 9, bits 18-19)
    function test_getFieldMode_withRecipientIsSponsorAtEnd() external {
        // Arrange - 0b11 in bits 18-19 = 0xC0000 (786432 in decimal)
        config = PolicyConfig.wrap(0x000C0000);

        // Act
        mode = config.getFieldMode(FIELD_RECIPIENT_IS_SPONSOR);

        // Assert
        assertEq(mode, MODE_CHECK_SUBPOLICY);
    }

    /// @notice Test extracting modes when multiple fields are set
    function test_getFieldMode_withMultipleFieldsSet() external {
        // Arrange - ARBITER=STORAGE(01), EXPIRY=CATCHALL(10), TOKEN_IN=SUBPOLICY(11)
        // bits: 0-1=01, 2-3=10, 4-5=11 = 0b110101 = 0x35
        config = PolicyConfig.wrap(0x00000039);

        // Act & Assert
        assertEq(config.getFieldMode(FIELD_ARBITER), MODE_CHECK_STORAGE);
        assertEq(config.getFieldMode(FIELD_EXPIRY), MODE_CHECK_CATCHALL);
        assertEq(config.getFieldMode(FIELD_TOKEN_IN), MODE_CHECK_SUBPOLICY);
    }

    /// @notice Fuzz test for getFieldMode
    /// @param _modeConfig Random mode config
    /// @param _fieldId Random field ID (bounded to valid range)
    function testFuzz_getFieldMode(uint32 _modeConfig, uint8 _fieldId) external {
        // Bound field ID to valid range
        _fieldId = uint8(bound(_fieldId, 0, 9));

        // Arrange
        config = PolicyConfig.wrap(_modeConfig);

        // Act
        mode = config.getFieldMode(_fieldId);

        // Assert - mode should always be 0-3
        assertLe(mode, 3);

        // Verify extraction is correct
        uint8 expected = uint8((_modeConfig >> (_fieldId * 2)) & 0x3);
        assertEq(mode, expected);
    }
}
