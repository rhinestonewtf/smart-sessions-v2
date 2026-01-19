// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import { BaseClaimPolicy_Unit_Test } from "../BaseClaimPolicy.t.sol";

// Interfaces
import { IERC165 } from "@openzeppelin/contracts/interfaces/IERC165.sol";
import { I1271Policy } from "@smartsessions/interfaces/IPolicy.sol";
import { IBaseClaimPolicy } from "@policies/claim/base/interfaces/IBaseClaimPolicy.sol";

/// @title BaseClaimPolicy.supportsInterface Unit Tests
/// @notice Unit tests for the supportsInterface function
contract BaseClaimPolicy_supportsInterface_Unit_Test is BaseClaimPolicy_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test returns true for IERC165 interfaceId
    function test_supportsInterface_withIERC165() external view {
        // Arrange
        bytes4 interfaceId = type(IERC165).interfaceId;

        // Act
        bool result = policy.supportsInterface(interfaceId);

        // Assert
        assertTrue(result);
    }

    /// @notice Test returns true for I1271Policy interfaceId
    function test_supportsInterface_withI1271Policy() external view {
        // Arrange
        bytes4 interfaceId = type(I1271Policy).interfaceId;

        // Act
        bool result = policy.supportsInterface(interfaceId);

        // Assert
        assertTrue(result);
    }

    /// @notice Test returns true for IBaseClaimPolicy interfaceId
    function test_supportsInterface_withIBaseClaimPolicy() external view {
        // Arrange
        bytes4 interfaceId = type(IBaseClaimPolicy).interfaceId;

        // Act
        bool result = policy.supportsInterface(interfaceId);

        // Assert
        assertTrue(result);
    }

    /// @notice Test returns false for unknown interfaceId
    function test_supportsInterface_withUnknownInterface() external view {
        // Arrange
        bytes4 interfaceId = bytes4(0xdeadbeef);

        // Act
        bool result = policy.supportsInterface(interfaceId);

        // Assert
        assertFalse(result);
    }

    /// @notice Test returns false for zero interfaceId
    function test_supportsInterface_withZeroInterface() external view {
        // Arrange
        bytes4 interfaceId = bytes4(0);

        // Act
        bool result = policy.supportsInterface(interfaceId);

        // Assert
        assertFalse(result);
    }

    /// @notice Fuzz test for supportsInterface
    function testFuzz_supportsInterface(bytes4 interfaceId) external view {
        // Act
        bool result = policy.supportsInterface(interfaceId);

        // Assert
        bool expected = interfaceId == type(IERC165).interfaceId
            || interfaceId == type(I1271Policy).interfaceId
            || interfaceId == type(IBaseClaimPolicy).interfaceId;
        assertEq(result, expected);
    }
}
