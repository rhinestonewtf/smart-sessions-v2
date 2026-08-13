// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import {
    NoncePinPolicy_Unit_Test
} from "@test/unit/policies/claim/NoncePinPolicy/NoncePinPolicy.t.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";

contract NoncePinPolicy_check1271SignedAction_Test is NoncePinPolicy_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                              FAIL CLOSED
    //////////////////////////////////////////////////////////////*/

    /// @notice An unconfigured entry must reject, not pass.
    /// @dev The claim policy family fails OPEN when unconfigured (empty mode config means
    ///      "check nothing"). This policy must not inherit that behaviour: a session whose pin
    ///      was never initialized would otherwise be silently unpinned, and unpinned means the
    ///      signer can mint a fresh nonce per digest and spend the session repeatedly.
    function test_check_uninitialized_shouldReturnFalse() public {
        vm.prank(address(this));
        bool result = noncePinPolicy.check1271SignedAction(
            configId, address(0), account, bytes32(0), _claimPayload(PINNED_NONCE)
        );

        assertFalse(result, "uninitialized config must fail closed");
    }

    /// @notice A payload too short to contain a nonce must reject rather than revert.
    function test_check_payloadTooShort_shouldReturnFalse() public {
        _pin(address(this), PINNED_NONCE);

        // 51 bytes: one short of the [20:52] nonce window
        bytes memory truncated = new bytes(51);

        bool result = noncePinPolicy.check1271SignedAction(
            configId, address(0), account, bytes32(0), truncated
        );

        assertFalse(result, "short payload must fail closed");
    }

    /// @notice An empty payload must reject rather than revert.
    function test_check_emptyPayload_shouldReturnFalse() public {
        _pin(address(this), PINNED_NONCE);

        bool result =
            noncePinPolicy.check1271SignedAction(configId, address(0), account, bytes32(0), "");

        assertFalse(result, "empty payload must fail closed");
    }

    /*//////////////////////////////////////////////////////////////
                             MATCHING NONCE
    //////////////////////////////////////////////////////////////*/

    /// @notice The pinned nonce is accepted.
    function test_check_matchingNonce_shouldReturnTrue() public {
        _pin(address(this), PINNED_NONCE);

        bool result = noncePinPolicy.check1271SignedAction(
            configId, address(0), account, bytes32(0), _claimPayload(PINNED_NONCE)
        );

        assertTrue(result, "pinned nonce must be accepted");
    }

    /// @notice A pinned nonce of zero is a real pin, not an unconfigured entry.
    /// @dev Guards the `configured` flag: without it, pinning zero would be indistinguishable
    ///      from never having been initialized.
    function test_check_pinnedZero_shouldReturnTrue() public {
        _pin(address(this), 0);

        bool result = noncePinPolicy.check1271SignedAction(
            configId, address(0), account, bytes32(0), _claimPayload(0)
        );

        assertTrue(result, "a pinned nonce of zero must be honoured");
    }

    /*//////////////////////////////////////////////////////////////
                            MISMATCHED NONCE
    //////////////////////////////////////////////////////////////*/

    /// @notice Any nonce other than the pinned one is rejected.
    /// @dev This is the property the whole design rests on. Without it the session signer picks
    ///      a fresh nonce per digest, each spend individually replay-protected by Permit2 but
    ///      the session itself unbounded.
    function test_check_mismatchedNonce_shouldReturnFalse() public {
        _pin(address(this), PINNED_NONCE);

        bool result = noncePinPolicy.check1271SignedAction(
            configId, address(0), account, bytes32(0), _claimPayload(PINNED_NONCE + 1)
        );

        assertFalse(result, "a non-pinned nonce must be rejected");
    }

    /// @notice Fuzz: only the pinned nonce is ever accepted.
    function testFuzz_check_onlyPinnedNonceAccepted(uint256 pinned, uint256 presented) public {
        _pin(address(this), pinned);

        bool result = noncePinPolicy.check1271SignedAction(
            configId, address(0), account, bytes32(0), _claimPayload(presented)
        );

        assertEq(result, pinned == presented, "acceptance must track nonce equality exactly");
    }

    /*//////////////////////////////////////////////////////////////
                            STORAGE ISOLATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Pins are isolated per multiplexer.
    /// @dev The caller is the multiplexer. A pin set by one must not be readable as another's,
    ///      or an unrelated session could satisfy this one's constraint.
    function test_check_isolatedPerMultiplexer() public {
        address otherMultiplexer = makeAddr("otherMultiplexer");
        _pin(address(this), PINNED_NONCE);

        // The other multiplexer never initialized, so it must fail closed
        vm.prank(otherMultiplexer);
        bool result = noncePinPolicy.check1271SignedAction(
            configId, address(0), account, bytes32(0), _claimPayload(PINNED_NONCE)
        );

        assertFalse(result, "a pin must not leak across multiplexers");
    }

    /// @notice Pins are isolated per account.
    function test_check_isolatedPerAccount() public {
        address otherAccount = makeAddr("otherAccount");
        _pin(address(this), PINNED_NONCE);

        bool result = noncePinPolicy.check1271SignedAction(
            configId, address(0), otherAccount, bytes32(0), _claimPayload(PINNED_NONCE)
        );

        assertFalse(result, "a pin must not leak across accounts");
    }

    /// @notice Pins are isolated per config.
    function test_check_isolatedPerConfig() public {
        ConfigId otherConfig = ConfigId.wrap(keccak256("other.config"));
        _pin(address(this), PINNED_NONCE);

        bool result = noncePinPolicy.check1271SignedAction(
            otherConfig, address(0), account, bytes32(0), _claimPayload(PINNED_NONCE)
        );

        assertFalse(result, "a pin must not leak across configs");
    }
}
