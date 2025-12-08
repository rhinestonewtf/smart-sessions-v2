// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import { Permit2ClaimPolicy_Unit_Test } from "../Permit2ClaimPolicy.t.sol";

// Interfaces
import { IERC165 } from "@openzeppelin/contracts/interfaces/IERC165.sol";
import { I1271Policy } from "@smartsessions/interfaces/IPolicy.sol";
import { IBaseClaimPolicy } from "@policies/claim/base/interfaces/IBaseClaimPolicy.sol";
import { IPermit2ClaimPolicy } from "@policies/claim/permit2/interfaces/IPermit2ClaimPolicy.sol";

/// @title Permit2ClaimPolicy.supportsInterface Unit Tests
/// @notice Unit tests for the supportsInterface function
contract Permit2ClaimPolicy_supportsInterface_Unit_Test is Permit2ClaimPolicy_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test supports IERC165 interface
    function test_supportsInterface_IERC165() external view {
        // Act
        bool supported = permit2ClaimPolicy.supportsInterface(type(IERC165).interfaceId);

        // Assert
        assertTrue(supported);
    }

    /// @notice Test supports I1271Policy interface
    function test_supportsInterface_I1271Policy() external view {
        // Act
        bool supported = permit2ClaimPolicy.supportsInterface(type(I1271Policy).interfaceId);

        // Assert
        assertTrue(supported);
    }

    /// @notice Test supports IBaseClaimPolicy interface
    function test_supportsInterface_IBaseClaimPolicy() external view {
        // Act
        bool supported = permit2ClaimPolicy.supportsInterface(type(IBaseClaimPolicy).interfaceId);

        // Assert
        assertTrue(supported);
    }

    /// @notice Test supports IPermit2ClaimPolicy interface
    function test_supportsInterface_IPermit2ClaimPolicy() external view {
        // Act
        bool supported = permit2ClaimPolicy.supportsInterface(type(IPermit2ClaimPolicy).interfaceId);

        // Assert
        assertTrue(supported);
    }

    /// @notice Test returns false for unsupported interface
    function test_supportsInterface_unsupported() external view {
        // Act
        bool supported = permit2ClaimPolicy.supportsInterface(bytes4(0xdeadbeef));

        // Assert
        assertFalse(supported);
    }
}
