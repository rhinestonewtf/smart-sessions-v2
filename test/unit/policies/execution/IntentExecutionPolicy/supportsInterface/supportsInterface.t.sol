// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import { IntentExecutionPolicy_Unit_Test } from "../IntentExecutionPolicy.t.sol";

// Interfaces
import { IActionPolicy } from "@smartsessions/interfaces/IPolicy.sol";
import { IERC165 } from "@openzeppelin/contracts/interfaces/IERC165.sol";

/// @title IntentExecutionPolicy.supportsInterface Unit Tests
/// @notice Unit tests for the supportsInterface function
contract IntentExecutionPolicy_supportsInterface_Unit_Test is IntentExecutionPolicy_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test returns true for IActionPolicy interface
    function test_supportsInterface_IActionPolicy() external view {
        // Act & Assert
        assertTrue(policy.supportsInterface(type(IActionPolicy).interfaceId));
    }

    /// @notice Test returns true for IERC165 interface
    function test_supportsInterface_IERC165() external view {
        // Act & Assert
        assertTrue(policy.supportsInterface(type(IERC165).interfaceId));
    }

    /// @notice Test returns false for unknown interface
    function test_supportsInterface_returnsFalse_forUnknown() external view {
        // Act & Assert
        assertFalse(policy.supportsInterface(0xdeadbeef));
    }
}
