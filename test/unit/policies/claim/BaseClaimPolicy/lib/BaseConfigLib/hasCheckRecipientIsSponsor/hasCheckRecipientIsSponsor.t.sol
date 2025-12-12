// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { BaseConfigLib_Unit_Test } from "../BaseConfigLib.t.sol";

// Libraries
import { BaseConfigLib, PolicyConfig } from "@policies/claim/base/lib/BaseConfigLib.sol";

/// @title BaseConfigLib.hasCheckRecipientIsSponsor Unit Tests
/// @notice Unit tests for the hasCheckRecipientIsSponsor function
contract BaseConfigLib_hasCheckRecipientIsSponsor_Unit_Test is BaseConfigLib_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using BaseConfigLib for PolicyConfig;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Result from hasCheckRecipientIsSponsor
    bool internal result;

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test returns false when mode is SKIP
    function test_hasCheckRecipientIsSponsor_withModeSkip() external {
        // Arrange - RECIPIENT_IS_SPONSOR bits 18-19 = 00
        config = PolicyConfig.wrap(0x00000000);

        // Act
        result = config.hasCheckRecipientIsSponsor();

        // Assert
        assertEq(result, false);
    }

    /// @notice Test returns true when mode is STORAGE
    function test_hasCheckRecipientIsSponsor_withModeStorage() external {
        // Arrange - RECIPIENT_IS_SPONSOR bits 18-19 = 01 = 0x40000
        config = PolicyConfig.wrap(0x00040000);

        // Act
        result = config.hasCheckRecipientIsSponsor();

        // Assert
        assertEq(result, true);
    }

    /// @notice Test returns true when mode is CATCHALL
    function test_hasCheckRecipientIsSponsor_withModeCatchall() external {
        // Arrange - RECIPIENT_IS_SPONSOR bits 18-19 = 10 = 0x80000
        config = PolicyConfig.wrap(0x00080000);

        // Act
        result = config.hasCheckRecipientIsSponsor();

        // Assert
        assertEq(result, true);
    }

    /// @notice Test returns true when mode is SUBPOLICY
    function test_hasCheckRecipientIsSponsor_withModeSubpolicy() external {
        // Arrange - RECIPIENT_IS_SPONSOR bits 18-19 = 11 = 0xC0000
        config = PolicyConfig.wrap(0x000C0000);

        // Act
        result = config.hasCheckRecipientIsSponsor();

        // Assert
        assertEq(result, true);
    }
}
