// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { BaseConfigLib_Unit_Test } from "../BaseConfigLib.t.sol";

// Libraries
import { BaseConfigLib } from "@policies/claim/base/lib/BaseConfigLib.sol";

/// @title BaseConfigLib.isStorageMode Unit Tests
/// @notice Unit tests for the isStorageMode function
contract BaseConfigLib_isStorageMode_Unit_Test is BaseConfigLib_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using BaseConfigLib for uint8;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Result from isStorageMode
    bool internal result;

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test MODE_SKIP returns false
    function test_isStorageMode_withModeSkip() external {
        // Act
        result = MODE_SKIP.isStorageMode();

        // Assert
        assertEq(result, false);
    }

    /// @notice Test MODE_CHECK_STORAGE returns true
    function test_isStorageMode_withModeStorage() external {
        // Act
        result = MODE_CHECK_STORAGE.isStorageMode();

        // Assert
        assertEq(result, true);
    }

    /// @notice Test MODE_CHECK_CATCHALL returns true
    function test_isStorageMode_withModeCatchall() external {
        // Act
        result = MODE_CHECK_CATCHALL.isStorageMode();

        // Assert
        assertEq(result, true);
    }

    /// @notice Test MODE_CHECK_SUBPOLICY returns false
    function test_isStorageMode_withModeSubpolicy() external {
        // Act
        result = MODE_CHECK_SUBPOLICY.isStorageMode();

        // Assert
        assertEq(result, false);
    }

    /// @notice Fuzz test - only modes 1 and 2 should return true
    function testFuzz_isStorageMode(uint8 _mode) external {
        // Act
        result = _mode.isStorageMode();

        // Assert
        bool expected = (_mode == 1 || _mode == 2);
        assertEq(result, expected);
    }
}
