// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { BaseConfigLib_Unit_Test } from "../BaseConfigLib.t.sol";

// Libraries
import { BaseConfigLib, PolicyConfig } from "@policies/claim/base/lib/BaseConfigLib.sol";

/// @title BaseConfigLib.hasAnyMandateCheck Unit Tests
/// @notice Unit tests for the hasAnyMandateCheck function
contract BaseConfigLib_hasAnyMandateCheck_Unit_Test is BaseConfigLib_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using BaseConfigLib for PolicyConfig;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Result from hasAnyMandateCheck
    bool internal result;

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test returns false when no mandate fields enabled
    function test_hasAnyMandateCheck_withNoMandateFields() external {
        // Arrange - only non-mandate fields set (ARBITER, EXPIRY, TOKEN_IN)
        config = PolicyConfig.wrap(0x00000015); // ARBITER=01, EXPIRY=01, TOKEN_IN=01

        // Act
        result = config.hasAnyMandateCheck();

        // Assert
        assertEq(result, false);
    }

    /// @notice Test returns true when target field enabled (RECIPIENT is part of mandate via
    /// target)
    function test_hasAnyMandateCheck_withRecipientEnabled() external {
        // Arrange - RECIPIENT bits 6-7 = 01 = 0x40
        config = PolicyConfig.wrap(0x00000040);

        // Act
        result = config.hasAnyMandateCheck();

        // Assert
        assertEq(result, true);
    }

    /// @notice Test returns true when ORIGIN_OPS enabled
    function test_hasAnyMandateCheck_withOriginOpsEnabled() external {
        // Arrange - ORIGIN_OPS bits 12-13 = 01 = 0x1000
        config = PolicyConfig.wrap(0x00001000);

        // Act
        result = config.hasAnyMandateCheck();

        // Assert
        assertEq(result, true);
    }

    /// @notice Test returns true when DEST_OPS enabled
    function test_hasAnyMandateCheck_withDestOpsEnabled() external {
        // Arrange - DEST_OPS bits 14-15 = 01 = 0x4000
        config = PolicyConfig.wrap(0x00004000);

        // Act
        result = config.hasAnyMandateCheck();

        // Assert
        assertEq(result, true);
    }

    /// @notice Test returns true when QUALIFICATION enabled
    function test_hasAnyMandateCheck_withQualificationEnabled() external {
        // Arrange - QUALIFICATION bits 16-17 = 01 = 0x10000
        config = PolicyConfig.wrap(0x00010000);

        // Act
        result = config.hasAnyMandateCheck();

        // Assert
        assertEq(result, true);
    }

    /// @notice Test returns true when multiple mandate fields enabled
    function test_hasAnyMandateCheck_withMultipleMandateFields() external {
        // Arrange - RECIPIENT=01, ORIGIN_OPS=01, DEST_OPS=01, QUALIFICATION=01
        config = PolicyConfig.wrap(0x00015040);

        // Act
        result = config.hasAnyMandateCheck();

        // Assert
        assertEq(result, true);
    }
}
