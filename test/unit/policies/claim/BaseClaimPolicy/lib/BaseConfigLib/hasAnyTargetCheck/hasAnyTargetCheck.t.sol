// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { BaseConfigLib_Unit_Test } from "../BaseConfigLib.t.sol";

// Libraries
import { BaseConfigLib, PolicyConfig } from "@policies/claim/base/lib/BaseConfigLib.sol";

/// @title BaseConfigLib.hasAnyTargetCheck Unit Tests
/// @notice Unit tests for the hasAnyTargetCheck function
contract BaseConfigLib_hasAnyTargetCheck_Unit_Test is BaseConfigLib_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using BaseConfigLib for PolicyConfig;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Result from hasAnyTargetCheck
    bool internal result;

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test returns false when no target fields enabled
    function test_hasAnyTargetCheck_withNoTargetFields() external {
        // Arrange - only non-target fields set (ARBITER, EXPIRY, TOKEN_IN)
        config = PolicyConfig.wrap(0x00000015); // ARBITER=01, EXPIRY=01, TOKEN_IN=01

        // Act
        result = config.hasAnyTargetCheck();

        // Assert
        assertEq(result, false);
    }

    /// @notice Test returns true when RECIPIENT enabled
    function test_hasAnyTargetCheck_withRecipientEnabled() external {
        // Arrange - RECIPIENT bits 6-7 = 01 = 0x40
        config = PolicyConfig.wrap(0x00000040);

        // Act
        result = config.hasAnyTargetCheck();

        // Assert
        assertEq(result, true);
    }

    /// @notice Test returns true when FILL_EXPIRY enabled
    function test_hasAnyTargetCheck_withFillExpiryEnabled() external {
        // Arrange - FILL_EXPIRY bits 8-9 = 01 = 0x100
        config = PolicyConfig.wrap(0x00000100);

        // Act
        result = config.hasAnyTargetCheck();

        // Assert
        assertEq(result, true);
    }

    /// @notice Test returns true when TOKEN_OUT enabled
    function test_hasAnyTargetCheck_withTokenOutEnabled() external {
        // Arrange - TOKEN_OUT bits 10-11 = 01 = 0x400
        config = PolicyConfig.wrap(0x00000400);

        // Act
        result = config.hasAnyTargetCheck();

        // Assert
        assertEq(result, true);
    }

    /// @notice Test returns true when RECIPIENT_IS_SPONSOR enabled
    function test_hasAnyTargetCheck_withRecipientIsSponsorEnabled() external {
        // Arrange - RECIPIENT_IS_SPONSOR bits 18-19 = 01 = 0x40000
        config = PolicyConfig.wrap(0x00040000);

        // Act
        result = config.hasAnyTargetCheck();

        // Assert
        assertEq(result, true);
    }

    /// @notice Test returns true when multiple target fields enabled
    function test_hasAnyTargetCheck_withMultipleTargetFields() external {
        // Arrange - RECIPIENT=01, FILL_EXPIRY=01, TOKEN_OUT=01
        config = PolicyConfig.wrap(0x00000540);

        // Act
        result = config.hasAnyTargetCheck();

        // Assert
        assertEq(result, true);
    }
}
