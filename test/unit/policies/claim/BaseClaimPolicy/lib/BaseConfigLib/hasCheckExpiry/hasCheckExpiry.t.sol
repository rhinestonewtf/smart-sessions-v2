// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { BaseConfigLib_Unit_Test } from "../BaseConfigLib.t.sol";

// Libraries
import { BaseConfigLib, PolicyConfig } from "@policies/claim/base/lib/BaseConfigLib.sol";

/// @title BaseConfigLib.hasCheckExpiry Unit Tests
/// @notice Unit tests for the hasCheckExpiry function
contract BaseConfigLib_hasCheckExpiry_Unit_Test is BaseConfigLib_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using BaseConfigLib for PolicyConfig;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Result from hasCheckExpiry
    bool internal result;

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test returns false when mode is SKIP
    function test_hasCheckExpiry_withModeSkip() external {
        // Arrange - EXPIRY bits 2-3 = 00
        config = PolicyConfig.wrap(0x00000000);

        // Act
        result = config.hasCheckExpiry();

        // Assert
        assertEq(result, false);
    }

    /// @notice Test returns true when mode is STORAGE
    function test_hasCheckExpiry_withModeStorage() external {
        // Arrange - EXPIRY bits 2-3 = 01 = 0x04
        config = PolicyConfig.wrap(0x00000004);

        // Act
        result = config.hasCheckExpiry();

        // Assert
        assertEq(result, true);
    }

    /// @notice Test returns true when mode is CATCHALL
    function test_hasCheckExpiry_withModeCatchall() external {
        // Arrange - EXPIRY bits 2-3 = 10 = 0x08
        config = PolicyConfig.wrap(0x00000008);

        // Act
        result = config.hasCheckExpiry();

        // Assert
        assertEq(result, true);
    }

    /// @notice Test returns true when mode is SUBPOLICY
    function test_hasCheckExpiry_withModeSubpolicy() external {
        // Arrange - EXPIRY bits 2-3 = 11 = 0x0C
        config = PolicyConfig.wrap(0x0000000C);

        // Act
        result = config.hasCheckExpiry();

        // Assert
        assertEq(result, true);
    }
}
