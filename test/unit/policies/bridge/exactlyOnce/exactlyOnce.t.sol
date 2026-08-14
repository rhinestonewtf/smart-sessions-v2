// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import {
    BridgeSessionPolicy_Unit_Test
} from "@test/unit/policies/bridge/BridgeSessionPolicy.t.sol";

// Types
import {
    LAYER_PERMIT2,
    LAYER_INTENT_EXECUTOR
} from "@policies/bridge/types/BridgeSessionDataTypes.sol";

/// @title BridgeSessionPolicy — exactly once across settlement layers
/// @notice The property the whole design exists for: the session authorizes every permitted layer,
/// and permits one settlement across all of them.
/// @dev Uniqueness WITHIN a layer is enforced by the settlement layer itself, before any policy
/// runs, so it is not re-tested here. These are the cross-layer cases, which are the only ones
/// this policy is responsible for.
contract BridgeSessionPolicy_exactlyOnce_Test is BridgeSessionPolicy_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                            EITHER ROUTE WORKS
    //////////////////////////////////////////////////////////////*/

    /// @dev The OR: nothing has settled, so either layer may go first
    function test_permit2SettlesFirst() public {
        _enable(PINNED);

        assertTrue(_check(_permit2Payload(PINNED)), "the Permit2 route must be open");
    }

    function test_executorSettlesFirst() public {
        _enable(PINNED);

        assertTrue(_check(_executorPayload(PINNED)), "the executor route must be open");
    }

    /*//////////////////////////////////////////////////////////////
                        ...BUT ONLY ONE OF THEM
    //////////////////////////////////////////////////////////////*/

    /// @dev Permit2 settled, so the executor route must close
    function test_permit2ThenExecutor_refused() public {
        _enable(PINNED);
        permit2.burn(account, PINNED);

        assertFalse(_check(_executorPayload(PINNED)), "the executor must see the Permit2 spend");
    }

    /// @dev The executor settled, so the Permit2 route must close
    function test_executorThenPermit2_refused() public {
        _enable(PINNED);
        executor.burnStandalone(PINNED, account);

        assertFalse(_check(_permit2Payload(PINNED)), "Permit2 must see the executor spend");
    }

    /// @dev The executor settles through three namespaces for one nonce value. Reading only the
    ///      standalone one would answer "not settled" for a settlement that already happened.
    function test_executorPermit2StubThenPermit2_refused() public {
        _enable(PINNED);
        executor.burnPermit2Stub(PINNED, account);

        assertFalse(_check(_permit2Payload(PINNED)), "the Permit2-stub namespace counts too");
    }

    function test_executorCompactThenPermit2_refused() public {
        _enable(PINNED);
        executor.burnCompact(PINNED, account);

        assertFalse(_check(_permit2Payload(PINNED)), "the compact namespace counts too");
    }

    /*//////////////////////////////////////////////////////////////
                       NEVER CHECK YOUR OWN LAYER
    //////////////////////////////////////////////////////////////*/

    /// @dev Permit2 burns the nonce BEFORE it validates, so by the time this policy runs the bit
    ///      is already set by the very settlement being validated. Checking it would reject every
    ///      legitimate Permit2 claim.
    function test_permit2DoesNotCheckItsOwnConsumable() public {
        _enable(PINNED);
        permit2.burn(account, PINNED);

        assertTrue(
            _check(_permit2Payload(PINNED)),
            "a Permit2 claim must not be rejected by Permit2's own burn"
        );
    }

    /// @dev Same for the executor, which also consumes before validating. Note this skips ONLY
    ///      the standalone namespace — the one a settlement through this layer actually burns.
    function test_executorDoesNotCheckItsOwnConsumable() public {
        _enable(PINNED);
        executor.burnStandalone(PINNED, account);

        assertTrue(
            _check(_executorPayload(PINNED)),
            "an executor settlement must not be rejected by its own burn"
        );
    }

    /// @dev The twins of the two Permit2-direction tests above, and the direction that was
    ///      originally missing. The executor keeps three independent namespaces but a settlement
    ///      through this layer burns only standalone, so a spend in either OTHER namespace is a
    ///      real prior settlement and must still exclude this one. Skipping per-layer rather than
    ///      per-consumable silently permitted a second spend.
    function test_executorCompactThenExecutor_refused() public {
        _enable(PINNED);
        executor.burnCompact(PINNED, account);

        assertFalse(
            _check(_executorPayload(PINNED)),
            "a compact-namespace spend must block a standalone settlement"
        );
    }

    function test_executorPermit2StubThenExecutor_refused() public {
        _enable(PINNED);
        executor.burnPermit2Stub(PINNED, account);

        assertFalse(
            _check(_executorPayload(PINNED)),
            "a Permit2-stub-namespace spend must block a standalone settlement"
        );
    }

    /*//////////////////////////////////////////////////////////////
                                THE PIN
    //////////////////////////////////////////////////////////////*/

    /// @dev Without this the signer mints a fresh digest per nonce and the session is unbounded -
    ///      the defect this whole design exists to fix
    function test_permit2OnAnotherNonce_refused() public {
        _enable(PINNED);

        assertFalse(_check(_permit2Payload(PINNED + 1)), "an unpinned Permit2 claim must fail");
    }

    function test_executorOnAnotherNonce_refused() public {
        _enable(PINNED);

        assertFalse(_check(_executorPayload(PINNED + 1)), "an unpinned settlement must fail");
    }

    /// @dev Each layer reads the nonce at its OWN offset. A payload carrying the pin at the other
    ///      layer's offset must not satisfy this one.
    function test_nonceReadAtTheLayersOwnOffset() public {
        _enable(PINNED);

        // A Permit2-shaped payload, tagged as the executor layer: the executor reads [22:54],
        // where a Permit2 payload has its deadline, not its nonce
        bytes memory mistagged = _permit2Payload(PINNED);
        mistagged[0] = bytes1(LAYER_INTENT_EXECUTOR);

        assertFalse(_check(mistagged), "the pin must be read at the settling layer's offset");
    }

    function testFuzz_onlyThePinnedNoncePasses(uint256 pinned, uint256 presented) public {
        _enable(pinned);

        assertEq(
            _check(_permit2Payload(presented)),
            pinned == presented,
            "exactly the pinned nonce may settle"
        );
    }

    /*//////////////////////////////////////////////////////////////
                              FAIL CLOSED
    //////////////////////////////////////////////////////////////*/

    function test_unconfigured_refused() public {
        assertFalse(_check(_permit2Payload(PINNED)), "an unconfigured session must fail closed");
    }

    /// @dev An unset entry reads nonce zero, so without the `configured` flag a session pinned to
    ///      zero and one never configured would be indistinguishable
    function test_unconfiguredWithZeroNonce_refused() public {
        assertFalse(_check(_permit2Payload(0)), "an unset entry must not pass as a zero pin");
    }

    function test_unknownLayerTag_refused() public {
        _enable(PINNED);

        bytes memory payload = _permit2Payload(PINNED);
        payload[0] = bytes1(uint8(7));

        assertFalse(_check(payload), "an unknown layer tag must be refused, not defaulted");
    }

    function test_emptyPayload_refused() public {
        _enable(PINNED);

        assertFalse(_check(""), "an empty payload must fail closed");
    }

    function test_payloadTooShortForNonce_refused() public {
        _enable(PINNED);

        assertFalse(_check(abi.encodePacked(uint8(LAYER_PERMIT2), address(0xA11CE))), "too short");
    }

    /*//////////////////////////////////////////////////////////////
                            THE LAYER IS REACHED
    //////////////////////////////////////////////////////////////*/

    /// @dev The settlement policy must actually be consulted and its verdict honoured, not
    ///      bypassed by a pin that happens to pass - without this every assertTrue above could be
    ///      vacuous. Consultation cannot be recorded by the mock: sub-policies are reached under
    ///      STATICCALL, so they cannot write. The verdict is the observable.
    function test_settlementPolicyRejectionIsHonoured() public {
        _enable(PINNED);

        vm.prank(multiplexer);
        bool result = policy.check1271SignedAction(
            configId, address(0), account, keccak256("a different digest"), _permit2Payload(PINNED)
        );

        assertFalse(result, "the settlement policy's rejection must be honoured");
    }

    /// @dev A layer the session did not permit has no policy installed
    function test_layerNotPermitted_refused() public {
        bytes memory initData = abi.encodePacked(
            bytes32(PINNED),
            uint8(1),
            uint8(LAYER_PERMIT2),
            address(permit2Layer),
            uint256(4),
            bytes4(0xdeadbeef)
        );

        vm.prank(multiplexer);
        policy.initializeWithMultiplexer(account, configId, initData);

        assertTrue(_check(_permit2Payload(PINNED)), "the permitted layer works");
        assertFalse(_check(_executorPayload(PINNED)), "an unpermitted layer must be refused");
    }
}
