// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { BaseConfigLib_Unit_Test } from "../BaseConfigLib.t.sol";

// Libraries
import { BaseConfigLib, PolicyConfig } from "@policies/claim/base/lib/BaseConfigLib.sol";

/// @title BaseConfigLib.hasCheckTokenIn Unit Tests
/// @notice Unit tests for the hasCheckTokenIn function
contract BaseConfigLib_hasCheckTokenIn_Unit_Test is BaseConfigLib_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using BaseConfigLib for PolicyConfig;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Result from hasCheckTokenIn
    bool internal result;

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test returns false when mode is SKIP
    function test_hasCheckTokenIn_withModeSkip() external {
        // Arrange - TOKEN_IN bits 4-5 = 00
        config = PolicyConfig.wrap(0x00000000);

        // Act
        result = config.hasCheckTokenIn();

        // Assert
        assertEq(result, false);
    }

    /// @notice Test returns true when mode is STORAGE
    function test_hasCheckTokenIn_withModeStorage() external {
        // Arrange - TOKEN_IN bits 4-5 = 01 = 0x10
        config = PolicyConfig.wrap(0x00000010);

        // Act
        result = config.hasCheckTokenIn();

        // Assert
        assertEq(result, true);
    }

    /// @notice Test returns true when mode is CATCHALL
    function test_hasCheckTokenIn_withModeCatchall() external {
        // Arrange - TOKEN_IN bits 4-5 = 10 = 0x20
        config = PolicyConfig.wrap(0x00000020);

        // Act
        result = config.hasCheckTokenIn();

        // Assert
        assertEq(result, true);
    }

    /// @notice Test returns true when mode is SUBPOLICY
    function test_hasCheckTokenIn_withModeSubpolicy() external {
        // Arrange - TOKEN_IN bits 4-5 = 11 = 0x30
        config = PolicyConfig.wrap(0x00000030);

        // Act
        result = config.hasCheckTokenIn();

        // Assert
        assertEq(result, true);
    }
}
