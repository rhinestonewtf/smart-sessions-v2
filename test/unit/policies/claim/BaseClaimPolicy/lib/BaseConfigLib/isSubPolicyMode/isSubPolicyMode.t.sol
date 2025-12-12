// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { BaseConfigLib_Unit_Test } from "../BaseConfigLib.t.sol";

// Libraries
import { BaseConfigLib } from "@policies/claim/base/lib/BaseConfigLib.sol";

/// @title BaseConfigLib.isSubPolicyMode Unit Tests
/// @notice Unit tests for the isSubPolicyMode function
contract BaseConfigLib_isSubPolicyMode_Unit_Test is BaseConfigLib_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using BaseConfigLib for uint8;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Result from isSubPolicyMode
    bool internal result;

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test MODE_SKIP returns false
    function test_isSubPolicyMode_withModeSkip() external {
        // Act
        result = MODE_SKIP.isSubPolicyMode();

        // Assert
        assertEq(result, false);
    }

    /// @notice Test MODE_CHECK_STORAGE returns false
    function test_isSubPolicyMode_withModeStorage() external {
        // Act
        result = MODE_CHECK_STORAGE.isSubPolicyMode();

        // Assert
        assertEq(result, false);
    }

    /// @notice Test MODE_CHECK_CATCHALL returns false
    function test_isSubPolicyMode_withModeCatchall() external {
        // Act
        result = MODE_CHECK_CATCHALL.isSubPolicyMode();

        // Assert
        assertEq(result, false);
    }

    /// @notice Test MODE_CHECK_SUBPOLICY returns true
    function test_isSubPolicyMode_withModeSubpolicy() external {
        // Act
        result = MODE_CHECK_SUBPOLICY.isSubPolicyMode();

        // Assert
        assertEq(result, true);
    }

    /// @notice Fuzz test - only mode 3 should return true
    function testFuzz_isSubPolicyMode(uint8 _mode) external {
        // Act
        result = _mode.isSubPolicyMode();

        // Assert
        bool expected = (_mode == 3);
        assertEq(result, expected);
    }
}
