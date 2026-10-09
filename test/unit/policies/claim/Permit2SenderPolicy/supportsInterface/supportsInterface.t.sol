// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import { Permit2SenderPolicy_Unit_Test } from "../Permit2SenderPolicy.t.sol";

// Interfaces
import { IActionPolicy, I1271Policy, IUserOpPolicy } from "@smartsessions/interfaces/IPolicy.sol";
import { IERC165 } from "@openzeppelin/contracts/interfaces/IERC165.sol";

/// @title Permit2SenderPolicy.supportsInterface Unit Tests
/// @notice Unit tests for the supportsInterface function
contract Permit2SenderPolicy_supportsInterface_Unit_Test is Permit2SenderPolicy_Unit_Test {
    /// @notice Test supports the ERC-1271 policy surface
    function test_supportsInterface_I1271Policy() external view {
        assertTrue(policy.supportsInterface(type(I1271Policy).interfaceId));
    }

    /// @notice Test supports IERC165
    function test_supportsInterface_IERC165() external view {
        assertTrue(policy.supportsInterface(type(IERC165).interfaceId));
    }

    /// @notice Test does not support the action policy surface
    function test_supportsInterface_IActionPolicy_returnsFalse() external view {
        assertFalse(policy.supportsInterface(type(IActionPolicy).interfaceId));
    }

    /// @notice Test does not support the user operation policy surface
    function test_supportsInterface_IUserOpPolicy_returnsFalse() external view {
        assertFalse(policy.supportsInterface(type(IUserOpPolicy).interfaceId));
    }

    /// @notice Test returns false for an unsupported interface
    function test_supportsInterface_unsupported_returnsFalse() external view {
        assertFalse(policy.supportsInterface(bytes4(0xdeadbeef)));
    }
}
