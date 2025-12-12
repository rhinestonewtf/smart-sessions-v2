// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { BaseConfigLib_Unit_Test } from "../BaseConfigLib.t.sol";

// Libraries
import { BaseConfigLib } from "@policies/claim/base/lib/BaseConfigLib.sol";

/// @title BaseConfigLib.getEffectiveChainId Unit Tests
/// @notice Unit tests for the getEffectiveChainId function
contract BaseConfigLib_getEffectiveChainId_Unit_Test is BaseConfigLib_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using BaseConfigLib for uint8;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Result effective chain ID
    uint256 internal effectiveChainId;

    /// @notice Test chain ID
    uint256 internal chainId;

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test MODE_CHECK_STORAGE returns actual chainId
    function test_getEffectiveChainId_withModeStorage() external {
        // Arrange
        chainId = 1;

        // Act
        effectiveChainId = MODE_CHECK_STORAGE.getEffectiveChainId(chainId);

        // Assert
        assertEq(effectiveChainId, 1);
    }

    /// @notice Test MODE_CHECK_CATCHALL returns 0
    function test_getEffectiveChainId_withModeCatchall() external {
        // Arrange
        chainId = 1;

        // Act
        effectiveChainId = MODE_CHECK_CATCHALL.getEffectiveChainId(chainId);

        // Assert
        assertEq(effectiveChainId, 0);
    }

    /// @notice Test MODE_SKIP returns actual chainId
    function test_getEffectiveChainId_withModeSkip() external {
        // Arrange
        chainId = 42;

        // Act
        effectiveChainId = MODE_SKIP.getEffectiveChainId(chainId);

        // Assert
        assertEq(effectiveChainId, 42);
    }

    /// @notice Test MODE_CHECK_SUBPOLICY returns actual chainId
    function test_getEffectiveChainId_withModeSubpolicy() external {
        // Arrange
        chainId = 137;

        // Act
        effectiveChainId = MODE_CHECK_SUBPOLICY.getEffectiveChainId(chainId);

        // Assert
        assertEq(effectiveChainId, 137);
    }

    /// @notice Fuzz test - only CATCHALL should return 0
    function testFuzz_getEffectiveChainId(uint8 _mode, uint256 _chainId) external {
        // Act
        effectiveChainId = _mode.getEffectiveChainId(_chainId);

        // Assert
        if (_mode == MODE_CHECK_CATCHALL) {
            assertEq(effectiveChainId, 0);
        } else {
            assertEq(effectiveChainId, _chainId);
        }
    }
}
