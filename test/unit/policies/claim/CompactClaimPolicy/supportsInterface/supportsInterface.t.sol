// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import { CompactClaimPolicy_Unit_Test } from "../CompactClaimPolicy.t.sol";

// Interfaces
import { IERC165 } from "@openzeppelin/contracts/interfaces/IERC165.sol";
import { I1271Policy } from "@smartsessions/interfaces/IPolicy.sol";
import { IBaseClaimPolicy } from "@policies/claim/base/interfaces/IBaseClaimPolicy.sol";
import { ICompactClaimPolicy } from "@policies/claim/compact/interfaces/ICompactClaimPolicy.sol";

/// @title CompactClaimPolicy.supportsInterface Unit Tests
/// @notice Unit tests for the supportsInterface function
contract CompactClaimPolicy_supportsInterface_Unit_Test is CompactClaimPolicy_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test supports IERC165 interface
    function test_supportsInterface_IERC165() external view {
        // Act
        bool supported = compactClaimPolicy.supportsInterface(type(IERC165).interfaceId);

        // Assert
        assertTrue(supported);
    }

    /// @notice Test supports I1271Policy interface
    function test_supportsInterface_I1271Policy() external view {
        // Act
        bool supported = compactClaimPolicy.supportsInterface(type(I1271Policy).interfaceId);

        // Assert
        assertTrue(supported);
    }

    /// @notice Test supports IBaseClaimPolicy interface
    function test_supportsInterface_IBaseClaimPolicy() external view {
        // Act
        bool supported = compactClaimPolicy.supportsInterface(type(IBaseClaimPolicy).interfaceId);

        // Assert
        assertTrue(supported);
    }

    /// @notice Test supports ICompactClaimPolicy interface
    function test_supportsInterface_ICompactClaimPolicy() external view {
        // Act
        bool supported = compactClaimPolicy.supportsInterface(type(ICompactClaimPolicy).interfaceId);

        // Assert
        assertTrue(supported);
    }

    /// @notice Test returns false for unsupported interface
    function test_supportsInterface_unsupported() external view {
        // Act
        bool supported = compactClaimPolicy.supportsInterface(bytes4(0xdeadbeef));

        // Assert
        assertFalse(supported);
    }
}
