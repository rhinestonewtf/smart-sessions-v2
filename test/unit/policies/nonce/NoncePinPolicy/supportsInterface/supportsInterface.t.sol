// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import {
    NoncePinPolicy_Unit_Test
} from "@test/unit/policies/nonce/NoncePinPolicy/NoncePinPolicy.t.sol";

// Interfaces
import { IERC165 } from "@openzeppelin/contracts/interfaces/IERC165.sol";
import { I1271Policy } from "@smartsessions/interfaces/IPolicy.sol";

/// @title NoncePinPolicy.supportsInterface Unit Tests
/// @notice Unit tests for the supportsInterface function
/// @dev Not cosmetic: smart sessions probes ERC-165 at install time and rejects the policy if
///      it answers false, so a wrong identifier here makes the policy uninstallable.
contract NoncePinPolicy_supportsInterface_Test is NoncePinPolicy_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test supports IERC165 interface
    function test_supportsInterface_IERC165() external view {
        // Act
        bool supported = noncePinPolicy.supportsInterface(type(IERC165).interfaceId);

        // Assert
        assertTrue(supported);
    }

    /// @notice Test supports I1271Policy interface
    function test_supportsInterface_I1271Policy() external view {
        // Act
        bool supported = noncePinPolicy.supportsInterface(type(I1271Policy).interfaceId);

        // Assert
        assertTrue(supported);
    }

    /// @notice Test does not support an unrelated interface
    function test_supportsInterface_unsupported() external view {
        // Act
        bool supported = noncePinPolicy.supportsInterface(bytes4(0xdeadbeef));

        // Assert
        assertFalse(supported);
    }

    /// @notice Test does not claim support for the ERC-165 invalid identifier
    function test_supportsInterface_invalidId() external view {
        // Act
        bool supported = noncePinPolicy.supportsInterface(bytes4(0xffffffff));

        // Assert
        assertFalse(supported);
    }
}
