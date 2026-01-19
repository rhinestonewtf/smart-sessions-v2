// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { BaseConfigLib_Unit_Test } from "../BaseConfigLib.t.sol";

// Libraries
import { BaseConfigLib, PolicyConfig } from "@policies/claim/base/lib/BaseConfigLib.sol";

/// @title BaseConfigLib.hasCheckArbiter Unit Tests
/// @notice Unit tests for the hasCheckArbiter function
contract BaseConfigLib_hasCheckArbiter_Unit_Test is BaseConfigLib_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using BaseConfigLib for PolicyConfig;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Result from hasCheckArbiter
    bool internal result;

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test returns false when mode is SKIP
    function test_hasCheckArbiter_withModeSkip() external {
        // Arrange - ARBITER bits 0-1 = 00
        config = PolicyConfig.wrap(0x00000000);

        // Act
        result = config.hasCheckArbiter();

        // Assert
        assertEq(result, false);
    }

    /// @notice Test returns true when mode is STORAGE
    function test_hasCheckArbiter_withModeStorage() external {
        // Arrange - ARBITER bits 0-1 = 01
        config = PolicyConfig.wrap(0x00000001);

        // Act
        result = config.hasCheckArbiter();

        // Assert
        assertEq(result, true);
    }

    /// @notice Test returns true when mode is CATCHALL
    function test_hasCheckArbiter_withModeCatchall() external {
        // Arrange - ARBITER bits 0-1 = 10
        config = PolicyConfig.wrap(0x00000002);

        // Act
        result = config.hasCheckArbiter();

        // Assert
        assertEq(result, true);
    }

    /// @notice Test returns true when mode is SUBPOLICY
    function test_hasCheckArbiter_withModeSubpolicy() external {
        // Arrange - ARBITER bits 0-1 = 11
        config = PolicyConfig.wrap(0x00000003);

        // Act
        result = config.hasCheckArbiter();

        // Assert
        assertEq(result, true);
    }
}
