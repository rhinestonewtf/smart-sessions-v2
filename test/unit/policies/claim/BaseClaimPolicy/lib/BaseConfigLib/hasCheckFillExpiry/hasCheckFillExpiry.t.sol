// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { BaseConfigLib_Unit_Test } from "../BaseConfigLib.t.sol";

// Libraries
import { BaseConfigLib, PolicyConfig } from "@policies/claim/base/lib/BaseConfigLib.sol";

/// @title BaseConfigLib.hasCheckFillExpiry Unit Tests
/// @notice Unit tests for the hasCheckFillExpiry function
contract BaseConfigLib_hasCheckFillExpiry_Unit_Test is BaseConfigLib_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using BaseConfigLib for PolicyConfig;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Result from hasCheckFillExpiry
    bool internal result;

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test returns false when mode is SKIP
    function test_hasCheckFillExpiry_withModeSkip() external {
        // Arrange - FILL_EXPIRY bits 8-9 = 00
        config = PolicyConfig.wrap(0x00000000);

        // Act
        result = config.hasCheckFillExpiry();

        // Assert
        assertEq(result, false);
    }

    /// @notice Test returns true when mode is STORAGE
    function test_hasCheckFillExpiry_withModeStorage() external {
        // Arrange - FILL_EXPIRY bits 8-9 = 01 = 0x100
        config = PolicyConfig.wrap(0x00000100);

        // Act
        result = config.hasCheckFillExpiry();

        // Assert
        assertEq(result, true);
    }

    /// @notice Test returns true when mode is CATCHALL
    function test_hasCheckFillExpiry_withModeCatchall() external {
        // Arrange - FILL_EXPIRY bits 8-9 = 10 = 0x200
        config = PolicyConfig.wrap(0x00000200);

        // Act
        result = config.hasCheckFillExpiry();

        // Assert
        assertEq(result, true);
    }

    /// @notice Test returns true when mode is SUBPOLICY
    function test_hasCheckFillExpiry_withModeSubpolicy() external {
        // Arrange - FILL_EXPIRY bits 8-9 = 11 = 0x300
        config = PolicyConfig.wrap(0x00000300);

        // Act
        result = config.hasCheckFillExpiry();

        // Assert
        assertEq(result, true);
    }
}
