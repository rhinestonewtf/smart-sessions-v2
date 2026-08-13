// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import {
    NoncePinPolicy_Unit_Test
} from "@test/unit/policies/nonce/NoncePinPolicy/NoncePinPolicy.t.sol";

/// @title NoncePinPolicy.getPinnedNonce Unit Tests
/// @notice Unit tests for the getPinnedNonce function
contract NoncePinPolicy_getPinnedNonce_Test is NoncePinPolicy_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice An uninitialized entry reports as unconfigured.
    function test_getPinnedNonce_uninitialized() public view {
        (bool configured, uint256 nonce) =
            noncePinPolicy.getPinnedNonce(configId, address(this), account);

        assertFalse(configured, "untouched entry should be unconfigured");
        assertEq(nonce, 0, "untouched entry should read zero");
    }

    /// @notice A configured entry reports its pin.
    function test_getPinnedNonce_configured() public {
        _pin(address(this), PINNED_NONCE);

        (bool configured, uint256 nonce) =
            noncePinPolicy.getPinnedNonce(configId, address(this), account);

        assertTrue(configured, "configured entry should report so");
        assertEq(nonce, PINNED_NONCE, "configured entry should report its pin");
    }

    /// @notice A pin of zero reads back as configured.
    /// @dev The pair exists precisely so that a legitimate pin of zero stays distinguishable
    ///      from an entry nobody ever wrote.
    function test_getPinnedNonce_configuredZero() public {
        _pin(address(this), 0);

        (bool configured, uint256 nonce) =
            noncePinPolicy.getPinnedNonce(configId, address(this), account);

        assertTrue(configured, "a pin of zero is still a pin");
        assertEq(nonce, 0, "stored nonce should be zero");
    }
}
