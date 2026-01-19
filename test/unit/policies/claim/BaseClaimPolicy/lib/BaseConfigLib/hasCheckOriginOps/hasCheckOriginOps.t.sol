// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { BaseConfigLib_Unit_Test } from "../BaseConfigLib.t.sol";

// Libraries
import { BaseConfigLib, PolicyConfig } from "@policies/claim/base/lib/BaseConfigLib.sol";

/// @title BaseConfigLib.hasCheckOriginOps Unit Tests
/// @notice Unit tests for the hasCheckOriginOps function
contract BaseConfigLib_hasCheckOriginOps_Unit_Test is BaseConfigLib_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using BaseConfigLib for PolicyConfig;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Result from hasCheckOriginOps
    bool internal result;

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test returns false when mode is SKIP
    function test_hasCheckOriginOps_withModeSkip() external {
        // Arrange - ORIGIN_OPS bits 12-13 = 00
        config = PolicyConfig.wrap(0x00000000);

        // Act
        result = config.hasCheckOriginOps();

        // Assert
        assertEq(result, false);
    }

    /// @notice Test returns true when mode is STORAGE
    function test_hasCheckOriginOps_withModeStorage() external {
        // Arrange - ORIGIN_OPS bits 12-13 = 01 = 0x1000
        config = PolicyConfig.wrap(0x00001000);

        // Act
        result = config.hasCheckOriginOps();

        // Assert
        assertEq(result, true);
    }

    /// @notice Test returns true when mode is CATCHALL
    function test_hasCheckOriginOps_withModeCatchall() external {
        // Arrange - ORIGIN_OPS bits 12-13 = 10 = 0x2000
        config = PolicyConfig.wrap(0x00002000);

        // Act
        result = config.hasCheckOriginOps();

        // Assert
        assertEq(result, true);
    }

    /// @notice Test returns true when mode is SUBPOLICY
    function test_hasCheckOriginOps_withModeSubpolicy() external {
        // Arrange - ORIGIN_OPS bits 12-13 = 11 = 0x3000
        config = PolicyConfig.wrap(0x00003000);

        // Act
        result = config.hasCheckOriginOps();

        // Assert
        assertEq(result, true);
    }
}
