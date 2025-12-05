// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { BaseConfigLib_Unit_Test } from "../BaseConfigLib.t.sol";

// Libraries
import { BaseConfigLib, PolicyConfig } from "@policies/claim/base/lib/BaseConfigLib.sol";

/// @title BaseConfigLib.setFieldMode Unit Tests
/// @notice Unit tests for the setFieldMode function
contract BaseConfigLib_setFieldMode_Unit_Test is BaseConfigLib_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using BaseConfigLib for PolicyConfig;
    using BaseConfigLib for uint32;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Result config from set operation
    uint32 internal resultConfig;

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test setting ARBITER to STORAGE on empty config
    function test_setFieldMode_withArbiterStorageOnEmpty() external {
        // Arrange
        modeConfig = 0x00000000;

        // Act
        resultConfig = modeConfig.setFieldMode(FIELD_ARBITER, MODE_CHECK_STORAGE);

        // Assert
        assertEq(resultConfig, 0x00000001);
    }

    /// @notice Test setting RECIPIENT to CATCHALL on empty config
    function test_setFieldMode_withRecipientCatchallOnEmpty() external {
        // Arrange
        modeConfig = 0x00000000;

        // Act
        resultConfig = modeConfig.setFieldMode(FIELD_RECIPIENT, MODE_CHECK_CATCHALL);

        // Assert - bits 6-7 = 10 = 0x80
        assertEq(resultConfig, 0x00000080);
    }

    /// @notice Test setting RECIPIENT_IS_SPONSOR to SUBPOLICY on empty config
    function test_setFieldMode_withRecipientIsSponsorSubpolicyOnEmpty() external {
        // Arrange
        modeConfig = 0x00000000;

        // Act
        resultConfig = modeConfig.setFieldMode(FIELD_RECIPIENT_IS_SPONSOR, MODE_CHECK_SUBPOLICY);

        // Assert - bits 18-19 = 11 = 0xC0000
        assertEq(resultConfig, 0x000C0000);
    }

    /// @notice Test overwriting existing mode
    function test_setFieldMode_withOverwriteExisting() external {
        // Arrange - ARBITER already set to STORAGE
        modeConfig = 0x00000001;

        // Act - change to SUBPOLICY
        resultConfig = modeConfig.setFieldMode(FIELD_ARBITER, MODE_CHECK_SUBPOLICY);

        // Assert
        assertEq(resultConfig, 0x00000003);
    }

    /// @notice Test setting different field preserves others
    function test_setFieldMode_withPreserveOtherFields() external {
        // Arrange - ARBITER=STORAGE, EXPIRY=CATCHALL
        modeConfig = 0x00000009; // bits 0-1=01, 2-3=10

        // Act - set TOKEN_IN to SUBPOLICY
        resultConfig = modeConfig.setFieldMode(FIELD_TOKEN_IN, MODE_CHECK_SUBPOLICY);

        // Assert - should be 0b110010_01 = 0x39 (but we need bits 4-5=11)
        // ARBITER(01) + EXPIRY(10) + TOKEN_IN(11) = 0b00111001 = 0x39
        assertEq(resultConfig, 0x00000039);

        // Verify other fields unchanged
        config = PolicyConfig.wrap(resultConfig);
        assertEq(PolicyConfig.wrap(resultConfig).getFieldMode(FIELD_ARBITER), MODE_CHECK_STORAGE);
        assertEq(PolicyConfig.wrap(resultConfig).getFieldMode(FIELD_EXPIRY), MODE_CHECK_CATCHALL);
    }

    /// @notice Test setting mode to SKIP clears bits
    function test_setFieldMode_withSetToSkip() external {
        // Arrange - ARBITER set to SUBPOLICY
        modeConfig = 0x00000003;

        // Act - set to SKIP
        resultConfig = modeConfig.setFieldMode(FIELD_ARBITER, MODE_SKIP);

        // Assert
        assertEq(resultConfig, 0x00000000);
    }

    /// @notice Fuzz test for setFieldMode
    /// @param _initialConfig Random initial config
    /// @param _fieldId Random field ID (bounded to valid range)
    /// @param _mode Random mode (bounded to valid range)
    function testFuzz_setFieldMode(uint32 _initialConfig, uint8 _fieldId, uint8 _mode) external {
        // Bound inputs
        _fieldId = uint8(bound(_fieldId, 0, 9));
        _mode = uint8(bound(_mode, 0, 3));

        // Act
        resultConfig = _initialConfig.setFieldMode(_fieldId, _mode);

        // Assert - verify the field was set correctly
        config = PolicyConfig.wrap(resultConfig);
        assertEq(config.getFieldMode(_fieldId), _mode);

        // Assert - verify other fields unchanged
        for (uint8 i = 0; i <= 9; i++) {
            if (i != _fieldId) {
                uint8 originalMode = uint8((_initialConfig >> (i * 2)) & 0x3);
                assertEq(config.getFieldMode(i), originalMode);
            }
        }
    }
}
