// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { BaseConfigLib_Unit_Test } from "../BaseConfigLib.t.sol";

// Libraries
import { BaseConfigLib, PolicyConfig } from "@policies/claim/base/lib/BaseConfigLib.sol";

/// @title BaseConfigLib.hasCheckTokenOut Unit Tests
/// @notice Unit tests for the hasCheckTokenOut function
contract BaseConfigLib_hasCheckTokenOut_Unit_Test is BaseConfigLib_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using BaseConfigLib for PolicyConfig;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Result from hasCheckTokenOut
    bool internal result;

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test returns false when mode is SKIP
    function test_hasCheckTokenOut_withModeSkip() external {
        // Arrange - TOKEN_OUT bits 10-11 = 00
        config = PolicyConfig.wrap(0x00000000);

        // Act
        result = config.hasCheckTokenOut();

        // Assert
        assertEq(result, false);
    }

    /// @notice Test returns true when mode is STORAGE
    function test_hasCheckTokenOut_withModeStorage() external {
        // Arrange - TOKEN_OUT bits 10-11 = 01 = 0x400
        config = PolicyConfig.wrap(0x00000400);

        // Act
        result = config.hasCheckTokenOut();

        // Assert
        assertEq(result, true);
    }

    /// @notice Test returns true when mode is CATCHALL
    function test_hasCheckTokenOut_withModeCatchall() external {
        // Arrange - TOKEN_OUT bits 10-11 = 10 = 0x800
        config = PolicyConfig.wrap(0x00000800);

        // Act
        result = config.hasCheckTokenOut();

        // Assert
        assertEq(result, true);
    }

    /// @notice Test returns true when mode is SUBPOLICY
    function test_hasCheckTokenOut_withModeSubpolicy() external {
        // Arrange - TOKEN_OUT bits 10-11 = 11 = 0xC00
        config = PolicyConfig.wrap(0x00000C00);

        // Act
        result = config.hasCheckTokenOut();

        // Assert
        assertEq(result, true);
    }
}
