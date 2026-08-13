// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import {
    NoncePinPolicy_Unit_Test
} from "@test/unit/policies/claim/NoncePinPolicy/NoncePinPolicy.t.sol";

// Contracts
import { NoncePinPolicy } from "@policies/claim/permit2/NoncePinPolicy.sol";

contract NoncePinPolicy_initializeWithMultiplexer_Test is NoncePinPolicy_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                 HAPPY
    //////////////////////////////////////////////////////////////*/

    /// @notice Initialization stores the nonce against the calling multiplexer.
    function test_initialize_shouldStoreNonce() public {
        _pin(address(this), PINNED_NONCE);

        (bool configured, uint256 nonce) =
            noncePinPolicy.getPinnedNonce(configId, address(this), account);

        assertTrue(configured, "entry should be marked configured");
        assertEq(nonce, PINNED_NONCE, "stored nonce should match init data");
    }

    /// @notice Re-initialization overwrites, as required of policies enabled without deinit.
    function test_initialize_shouldOverwriteOnReinit() public {
        _pin(address(this), PINNED_NONCE);
        _pin(address(this), PINNED_NONCE + 7);

        (bool configured, uint256 nonce) =
            noncePinPolicy.getPinnedNonce(configId, address(this), account);

        assertTrue(configured, "entry should remain configured");
        assertEq(nonce, PINNED_NONCE + 7, "re-initialization should overwrite the pin");
    }

    /// @notice Fuzz: any nonce round-trips through initialization.
    function testFuzz_initialize_roundTrips(uint256 pinned) public {
        _pin(address(this), pinned);

        (bool configured, uint256 nonce) =
            noncePinPolicy.getPinnedNonce(configId, address(this), account);

        assertTrue(configured, "entry should be marked configured");
        assertEq(nonce, pinned, "stored nonce should match init data");
    }

    /*//////////////////////////////////////////////////////////////
                              MALFORMED
    //////////////////////////////////////////////////////////////*/

    /// @notice Init data must be exactly one word.
    /// @dev Reverting rather than silently accepting matters: a short or padded blob that
    ///      decoded to the wrong nonce would produce a session pinned to a value nobody
    ///      intended, which fails only later and confusingly.
    function test_initialize_shortInitData_shouldRevert() public {
        bytes memory tooShort = new bytes(31);

        vm.expectRevert(
            abi.encodeWithSelector(NoncePinPolicy.InvalidInitDataLength.selector, uint256(31))
        );
        noncePinPolicy.initializeWithMultiplexer(account, configId, tooShort);
    }

    /// @notice Over-long init data is rejected too.
    function test_initialize_longInitData_shouldRevert() public {
        bytes memory tooLong = new bytes(33);

        vm.expectRevert(
            abi.encodeWithSelector(NoncePinPolicy.InvalidInitDataLength.selector, uint256(33))
        );
        noncePinPolicy.initializeWithMultiplexer(account, configId, tooLong);
    }

    /// @notice Empty init data is rejected.
    function test_initialize_emptyInitData_shouldRevert() public {
        vm.expectRevert(
            abi.encodeWithSelector(NoncePinPolicy.InvalidInitDataLength.selector, uint256(0))
        );
        noncePinPolicy.initializeWithMultiplexer(account, configId, "");
    }

    /*//////////////////////////////////////////////////////////////
                            STORAGE ISOLATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Two multiplexers pinning the same config keep independent entries.
    function test_initialize_isolatedPerMultiplexer() public {
        address otherMultiplexer = makeAddr("otherMultiplexer");

        _pin(address(this), PINNED_NONCE);
        _pin(otherMultiplexer, PINNED_NONCE + 1);

        (, uint256 mine) = noncePinPolicy.getPinnedNonce(configId, address(this), account);
        (, uint256 theirs) = noncePinPolicy.getPinnedNonce(configId, otherMultiplexer, account);

        assertEq(mine, PINNED_NONCE, "own pin should be untouched");
        assertEq(theirs, PINNED_NONCE + 1, "other multiplexer should keep its own pin");
    }

    /// @notice An uninitialized entry reports as unconfigured.
    function test_getPinnedNonce_uninitialized() public view {
        (bool configured, uint256 nonce) =
            noncePinPolicy.getPinnedNonce(configId, address(this), account);

        assertFalse(configured, "untouched entry should be unconfigured");
        assertEq(nonce, 0, "untouched entry should read zero");
    }
}
