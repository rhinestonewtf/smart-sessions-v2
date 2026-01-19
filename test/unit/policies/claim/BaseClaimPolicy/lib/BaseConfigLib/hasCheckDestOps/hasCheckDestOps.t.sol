// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { BaseConfigLib_Unit_Test } from "../BaseConfigLib.t.sol";

// Libraries
import { BaseConfigLib, PolicyConfig } from "@policies/claim/base/lib/BaseConfigLib.sol";

/// @title BaseConfigLib.hasCheckDestOps Unit Tests
/// @notice Unit tests for the hasCheckDestOps function
contract BaseConfigLib_hasCheckDestOps_Unit_Test is BaseConfigLib_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using BaseConfigLib for PolicyConfig;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Result from hasCheckDestOps
    bool internal result;

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test returns false when mode is SKIP
    function test_hasCheckDestOps_withModeSkip() external {
        // Arrange - DEST_OPS bits 14-15 = 00
        config = PolicyConfig.wrap(0x00000000);

        // Act
        result = config.hasCheckDestOps();

        // Assert
        assertEq(result, false);
    }

    /// @notice Test returns true when mode is STORAGE
    function test_hasCheckDestOps_withModeStorage() external {
        // Arrange - DEST_OPS bits 14-15 = 01 = 0x4000
        config = PolicyConfig.wrap(0x00004000);

        // Act
        result = config.hasCheckDestOps();

        // Assert
        assertEq(result, true);
    }

    /// @notice Test returns true when mode is CATCHALL
    function test_hasCheckDestOps_withModeCatchall() external {
        // Arrange - DEST_OPS bits 14-15 = 10 = 0x8000
        config = PolicyConfig.wrap(0x00008000);

        // Act
        result = config.hasCheckDestOps();

        // Assert
        assertEq(result, true);
    }

    /// @notice Test returns true when mode is SUBPOLICY
    function test_hasCheckDestOps_withModeSubpolicy() external {
        // Arrange - DEST_OPS bits 14-15 = 11 = 0xC000
        config = PolicyConfig.wrap(0x0000C000);

        // Act
        result = config.hasCheckDestOps();

        // Assert
        assertEq(result, true);
    }
}
