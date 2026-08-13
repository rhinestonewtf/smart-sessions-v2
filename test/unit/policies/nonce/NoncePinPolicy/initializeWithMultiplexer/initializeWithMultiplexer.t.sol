// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import {
    NoncePinPolicy_Unit_Test
} from "@test/unit/policies/nonce/NoncePinPolicy/NoncePinPolicy.t.sol";

// Contracts
import { INoncePinPolicy } from "@policies/nonce/interfaces/INoncePinPolicy.sol";

// Interfaces
import { IPolicy } from "@smartsessions/interfaces/IPolicy.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";

/// @title NoncePinPolicy.initializeWithMultiplexer Unit Tests
/// @notice Unit tests for the initializeWithMultiplexer function
contract NoncePinPolicy_initializeWithMultiplexer_Test is NoncePinPolicy_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                 HAPPY
    //////////////////////////////////////////////////////////////*/

    /// @notice Initialization stores the nonce against the calling multiplexer.
    function test_initializeWithMultiplexer_shouldStoreNonce() public {
        _pin(address(this), PINNED_NONCE);

        (bool configured, uint256 nonce) =
            noncePinPolicy.getPinnedNonce(configId, address(this), account);

        assertTrue(configured, "entry should be marked configured");
        assertEq(nonce, PINNED_NONCE, "stored nonce should match init data");
    }

    /// @notice Initialization announces itself.
    /// @dev Indexers and the enable flow rely on this event to observe which policies were
    ///      configured for a session.
    function test_initializeWithMultiplexer_shouldEmitPolicySet() public {
        vm.expectEmit(true, true, true, true);
        emit IPolicy.PolicySet(configId, address(this), account);

        noncePinPolicy.initializeWithMultiplexer(account, configId, abi.encode(PINNED_NONCE));
    }

    /// @notice Re-initialization overwrites, as required of policies enabled without deinit.
    function test_initializeWithMultiplexer_shouldOverwriteOnReinit() public {
        _pin(address(this), PINNED_NONCE);
        _pin(address(this), PINNED_NONCE + 7);

        (bool configured, uint256 nonce) =
            noncePinPolicy.getPinnedNonce(configId, address(this), account);

        assertTrue(configured, "entry should remain configured");
        assertEq(nonce, PINNED_NONCE + 7, "re-initialization should overwrite the pin");
    }

    /// @notice Fuzz: any nonce round-trips through initialization.
    function testFuzz_initializeWithMultiplexer_roundTrips(uint256 pinned) public {
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
    function test_initializeWithMultiplexer_shortInitData_shouldRevert() public {
        bytes memory tooShort = new bytes(31);

        vm.expectRevert(
            abi.encodeWithSelector(INoncePinPolicy.InvalidInitDataLength.selector, uint256(31))
        );
        noncePinPolicy.initializeWithMultiplexer(account, configId, tooShort);
    }

    /// @notice Over-long init data is rejected too.
    function test_initializeWithMultiplexer_longInitData_shouldRevert() public {
        bytes memory tooLong = new bytes(33);

        vm.expectRevert(
            abi.encodeWithSelector(INoncePinPolicy.InvalidInitDataLength.selector, uint256(33))
        );
        noncePinPolicy.initializeWithMultiplexer(account, configId, tooLong);
    }

    /// @notice Empty init data is rejected.
    function test_initializeWithMultiplexer_emptyInitData_shouldRevert() public {
        vm.expectRevert(
            abi.encodeWithSelector(INoncePinPolicy.InvalidInitDataLength.selector, uint256(0))
        );
        noncePinPolicy.initializeWithMultiplexer(account, configId, "");
    }

    /// @notice Fuzz: any length other than one word is rejected.
    function testFuzz_initializeWithMultiplexer_wrongLengthAlwaysReverts(uint8 length) public {
        vm.assume(length != 32);

        vm.expectRevert(
            abi.encodeWithSelector(INoncePinPolicy.InvalidInitDataLength.selector, uint256(length))
        );
        noncePinPolicy.initializeWithMultiplexer(account, configId, new bytes(length));
    }

    /*//////////////////////////////////////////////////////////////
                            STORAGE ISOLATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Two multiplexers pinning the same config keep independent entries.
    function test_initializeWithMultiplexer_isolatedPerMultiplexer() public {
        address otherMultiplexer = makeAddr("otherMultiplexer");

        _pin(address(this), PINNED_NONCE);
        _pin(otherMultiplexer, PINNED_NONCE + 1);

        (, uint256 mine) = noncePinPolicy.getPinnedNonce(configId, address(this), account);
        (, uint256 theirs) = noncePinPolicy.getPinnedNonce(configId, otherMultiplexer, account);

        assertEq(mine, PINNED_NONCE, "own pin should be untouched");
        assertEq(theirs, PINNED_NONCE + 1, "other multiplexer should keep its own pin");
    }

    /// @notice Pins are isolated per account and per config.
    function test_initializeWithMultiplexer_isolatedPerAccountAndConfig() public {
        address otherAccount = makeAddr("otherAccount");
        ConfigId otherConfig = ConfigId.wrap(keccak256("other.config"));

        _pin(address(this), PINNED_NONCE);

        (bool otherAccountConfigured,) =
            noncePinPolicy.getPinnedNonce(configId, address(this), otherAccount);
        (bool otherConfigConfigured,) =
            noncePinPolicy.getPinnedNonce(otherConfig, address(this), account);

        assertFalse(otherAccountConfigured, "a pin must not leak across accounts");
        assertFalse(otherConfigConfigured, "a pin must not leak across configs");
    }
}
