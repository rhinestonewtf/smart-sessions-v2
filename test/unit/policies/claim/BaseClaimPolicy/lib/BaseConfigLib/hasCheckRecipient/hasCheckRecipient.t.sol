// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { BaseConfigLib_Unit_Test } from "../BaseConfigLib.t.sol";

// Libraries
import { BaseConfigLib, PolicyConfig } from "@policies/claim/base/lib/BaseConfigLib.sol";

/// @title BaseConfigLib.hasCheckRecipient Unit Tests
/// @notice Unit tests for the hasCheckRecipient function
contract BaseConfigLib_hasCheckRecipient_Unit_Test is BaseConfigLib_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using BaseConfigLib for PolicyConfig;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Result from hasCheckRecipient
    bool internal result;

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test returns false when mode is SKIP
    function test_hasCheckRecipient_withModeSkip() external {
        // Arrange - RECIPIENT bits 6-7 = 00
        config = PolicyConfig.wrap(0x00000000);

        // Act
        result = config.hasCheckRecipient();

        // Assert
        assertEq(result, false);
    }

    /// @notice Test returns true when mode is STORAGE
    function test_hasCheckRecipient_withModeStorage() external {
        // Arrange - RECIPIENT bits 6-7 = 01 = 0x40
        config = PolicyConfig.wrap(0x00000040);

        // Act
        result = config.hasCheckRecipient();

        // Assert
        assertEq(result, true);
    }

    /// @notice Test returns true when mode is CATCHALL
    function test_hasCheckRecipient_withModeCatchall() external {
        // Arrange - RECIPIENT bits 6-7 = 10 = 0x80
        config = PolicyConfig.wrap(0x00000080);

        // Act
        result = config.hasCheckRecipient();

        // Assert
        assertEq(result, true);
    }

    /// @notice Test returns true when mode is SUBPOLICY
    function test_hasCheckRecipient_withModeSubpolicy() external {
        // Arrange - RECIPIENT bits 6-7 = 11 = 0xC0
        config = PolicyConfig.wrap(0x000000C0);

        // Act
        result = config.hasCheckRecipient();

        // Assert
        assertEq(result, true);
    }
}
