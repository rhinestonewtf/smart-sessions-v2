// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { BaseConfigLib_Unit_Test } from "../BaseConfigLib.t.sol";

// Libraries
import { BaseConfigLib, PolicyConfig } from "@policies/claim/base/lib/BaseConfigLib.sol";

/// @title BaseConfigLib.hasCheckQualification Unit Tests
/// @notice Unit tests for the hasCheckQualification function
contract BaseConfigLib_hasCheckQualification_Unit_Test is BaseConfigLib_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using BaseConfigLib for PolicyConfig;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Result from hasCheckQualification
    bool internal result;

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test returns false when mode is SKIP
    function test_hasCheckQualification_withModeSkip() external {
        // Arrange - QUALIFICATION bits 16-17 = 00
        config = PolicyConfig.wrap(0x00000000);

        // Act
        result = config.hasCheckQualification();

        // Assert
        assertEq(result, false);
    }

    /// @notice Test returns true when mode is STORAGE
    function test_hasCheckQualification_withModeStorage() external {
        // Arrange - QUALIFICATION bits 16-17 = 01 = 0x10000
        config = PolicyConfig.wrap(0x00010000);

        // Act
        result = config.hasCheckQualification();

        // Assert
        assertEq(result, true);
    }

    /// @notice Test returns true when mode is CATCHALL
    function test_hasCheckQualification_withModeCatchall() external {
        // Arrange - QUALIFICATION bits 16-17 = 10 = 0x20000
        config = PolicyConfig.wrap(0x00020000);

        // Act
        result = config.hasCheckQualification();

        // Assert
        assertEq(result, true);
    }

    /// @notice Test returns true when mode is SUBPOLICY
    function test_hasCheckQualification_withModeSubpolicy() external {
        // Arrange - QUALIFICATION bits 16-17 = 11 = 0x30000
        config = PolicyConfig.wrap(0x00030000);

        // Act
        result = config.hasCheckQualification();

        // Assert
        assertEq(result, true);
    }
}
