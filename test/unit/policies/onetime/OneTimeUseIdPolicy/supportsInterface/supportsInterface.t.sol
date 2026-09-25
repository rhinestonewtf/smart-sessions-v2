// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import { OneTimeUseIdPolicy_Unit_Test } from "../OneTimeUseIdPolicy.t.sol";

// Interfaces
import { IActionPolicy, I1271Policy } from "@smartsessions/interfaces/IPolicy.sol";
import { IOneTimeUseIdPolicy } from "@policies/onetime/interfaces/IOneTimeUseIdPolicy.sol";
import { IERC165 } from "@openzeppelin/contracts/interfaces/IERC165.sol";

/// @title OneTimeUseIdPolicy.supportsInterface Unit Tests
/// @notice Unit tests for the supportsInterface function
contract OneTimeUseIdPolicy_supportsInterface_Unit_Test is OneTimeUseIdPolicy_Unit_Test {
    /// @notice Test supports the action policy surface
    function test_supportsInterface_IActionPolicy() external view {
        assertTrue(policy.supportsInterface(type(IActionPolicy).interfaceId));
    }

    /// @notice Test supports the ERC-1271 policy surface
    function test_supportsInterface_I1271Policy() external view {
        assertTrue(policy.supportsInterface(type(I1271Policy).interfaceId));
    }

    /// @notice Test supports its own view surface
    function test_supportsInterface_IOneTimeUseIdPolicy() external view {
        assertTrue(policy.supportsInterface(type(IOneTimeUseIdPolicy).interfaceId));
    }

    /// @notice Test supports IERC165
    function test_supportsInterface_IERC165() external view {
        assertTrue(policy.supportsInterface(type(IERC165).interfaceId));
    }

    /// @notice Test returns false for an unsupported interface
    function test_supportsInterface_unsupported_returnsFalse() external view {
        assertFalse(policy.supportsInterface(bytes4(0xdeadbeef)));
    }
}
