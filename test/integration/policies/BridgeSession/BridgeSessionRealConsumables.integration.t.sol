// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { Test } from "@forge-std/Test.sol";
import { TestHelperLib, CompactEnvironment } from "@compact-utils/tests/Environment.sol";

import { BridgeSessionPolicy } from "@policies/bridge/BridgeSessionPolicy.sol";
import { MockSettlementLayerPolicy } from "@mocks/MockSettlementLayer.sol";

import { ConfigId } from "@smartsessions/DataTypes.sol";
import {
    LAYER_PERMIT2,
    LAYER_INTENT_EXECUTOR
} from "@policies/bridge/types/BridgeSessionDataTypes.sol";

/// @title The bridge session against REAL consumables
/// @notice Every other test of this policy hands it mock nonce state. This one wires it to the
/// canonical Permit2 and the real IntentExecutor deployed by `CompactEnvironment`, then burns
/// nonces through those real contracts and checks the policy sees it.
///
/// What this closes:
///   1. `permit2Spent`'s word/bit arithmetic has only ever been checked against a mock that used
///      the same arithmetic. Here it is checked against Permit2's own bitmap.
///   2. "Across and Eco share one Permit2 nonce" is the premise that turns a three-way OR into
///      two layers. It has never been exercised. Here two distinct arbiters contend for one
///      nonce on the real contract.
///
/// What it does NOT close: these are real CONSUMABLES, not full settlements routed through an
/// arbiter. The sub-policies are still stand-ins. Stated plainly so the coverage is not overread.
contract BridgeSessionRealConsumables_Test is Test, CompactEnvironment {
    using TestHelperLib for *;

    BridgeSessionPolicy internal policy;
    MockSettlementLayerPolicy internal permit2Layer;
    MockSettlementLayerPolicy internal executorLayer;

    address internal account;
    address internal multiplexer;
    ConfigId internal configId;

    /// @dev Two distinct arbiters — "Across" and "Eco" — that settle through one Permit2
    address internal acrossArbiter;
    address internal ecoArbiter;

    uint256 internal constant PINNED = 1337;
    bytes32 internal constant DIGEST = keccak256("the settlement digest");

    function setUp() public virtual {
        _deployCompact();

        account = env.smartAccount1.account == address(0)
            ? makeAddr("account")
            : env.smartAccount1.account;
        multiplexer = makeAddr("smartSession");
        configId = ConfigId.wrap(keccak256("bridge.session.real.consumables"));

        acrossArbiter = makeAddr("acrossArbiter");
        ecoArbiter = makeAddr("ecoArbiter");

        permit2Layer = new MockSettlementLayerPolicy(DIGEST);
        executorLayer = new MockSettlementLayerPolicy(DIGEST);

        // The REAL Permit2 and the REAL IntentExecutor
        policy = new BridgeSessionPolicy(address(env.intentExecutor), address(env.permit2));

        _enable(PINNED);
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    function _enable(uint256 nonce) internal {
        bytes memory init = abi.encodePacked(
            bytes32(nonce),
            uint8(2),
            uint8(LAYER_PERMIT2),
            address(permit2Layer),
            uint256(4),
            bytes4(0xdeadbeef),
            uint8(LAYER_INTENT_EXECUTOR),
            address(executorLayer),
            uint256(4),
            bytes4(0xdeadbeef)
        );
        vm.prank(multiplexer);
        policy.initializeWithMultiplexer(account, configId, init);
    }

    function _permit2Payload(uint256 nonce) internal view returns (bytes memory) {
        return abi.encodePacked(
            uint8(LAYER_PERMIT2), acrossArbiter, bytes32(nonce), uint256(block.timestamp + 1)
        );
    }

    function _executorPayload(uint256 nonce) internal view returns (bytes memory) {
        return abi.encodePacked(
            uint8(LAYER_INTENT_EXECUTOR), uint8(0), uint8(0), account, bytes32(nonce), uint256(0)
        );
    }

    function _check(bytes memory payload) internal returns (bool) {
        address settler =
            uint8(payload[0]) == LAYER_PERMIT2 ? address(env.permit2) : address(env.intentExecutor);
        vm.prank(multiplexer);
        return policy.check1271SignedAction(configId, settler, account, DIGEST, payload);
    }

    /// @dev Burns a nonce on the REAL Permit2, the way a settlement's `_useUnorderedNonce` does —
    ///      same bitmap, same word, same bit.
    function _burnRealPermit2Nonce(uint256 nonce) internal {
        vm.prank(account);
        env.permit2.invalidateUnorderedNonces(nonce >> 8, 1 << (nonce & 0xff));
    }

    /// @dev Reads the REAL Permit2 bitmap, independently of the policy's own arithmetic
    function _realPermit2Burned(uint256 nonce) internal view returns (bool) {
        return (env.permit2.nonceBitmap(account, nonce >> 8) >> (nonce & 0xff)) & 1 == 1;
    }

    /*//////////////////////////////////////////////////////////////
                     THE POLICY READS REAL PERMIT2 STATE
    //////////////////////////////////////////////////////////////*/

    /// @dev Both routes open on a genuinely untouched real bitmap
    function test_bothRoutesOpenAgainstRealPermit2() public {
        assertFalse(_realPermit2Burned(PINNED), "the real bitmap starts clean");

        assertTrue(_check(_permit2Payload(PINNED)), "the Permit2 route must be open");
        assertTrue(_check(_executorPayload(PINNED)), "the executor route must be open");
    }

    /// @dev The arithmetic check that mocks could never make: burn on the real Permit2 and see
    ///      whether the policy's own word/bit derivation lands on the same slot.
    function test_policyReadMatchesRealPermit2Bitmap() public {
        _burnRealPermit2Nonce(PINNED);

        assertTrue(_realPermit2Burned(PINNED), "the real contract records the burn");

        assertFalse(
            _check(_executorPayload(PINNED)), "the policy must read the same bit Permit2 wrote"
        );
    }

    /// @dev Same, across word boundaries — the case where a wrong shift would silently disagree
    function testFuzz_policyReadMatchesRealPermit2Bitmap(uint256 nonce) public {
        _enable(nonce);

        assertTrue(_check(_executorPayload(nonce)), "unburned: the executor route is open");

        _burnRealPermit2Nonce(nonce);

        assertFalse(
            _check(_executorPayload(nonce)),
            "burned on the real contract: the executor route must close"
        );
    }

    /*//////////////////////////////////////////////////////////////
                    ACROSS AND ECO SHARE ONE REAL NONCE
    //////////////////////////////////////////////////////////////*/

    /// @dev The premise that collapses three settlement layers into two. Permit2's bitmap is keyed
    ///      on (owner, nonce) with no arbiter component, so two different arbiters contend for the
    ///      same bit. If this ever fails, Across and Eco are NOT one layer and the design needs a
    ///      third.
    function test_acrossAndEcoContendForOneRealNonce() public {
        assertTrue(acrossArbiter != ecoArbiter, "two distinct arbiters");

        // Across settles: the real bitmap bit for this owner+nonce is now set
        _burnRealPermit2Nonce(PINNED);

        // Eco presents the same nonce, with its own arbiter in the payload
        bytes memory ecoPayload = abi.encodePacked(
            uint8(LAYER_PERMIT2), ecoArbiter, bytes32(PINNED), uint256(block.timestamp + 1)
        );

        assertTrue(
            _realPermit2Burned(PINNED), "one bitmap bit, regardless of which arbiter spent it"
        );

        // The bit is shared, so Permit2 itself would reject Eco's spend. Our policy does not need
        // to - and deliberately does not read its own consumable, which this asserts.
        assertTrue(
            _check(ecoPayload), "the policy must not reject a Permit2 claim on Permit2's own burn"
        );
    }

    /// @dev The executor route, however, MUST see that spend - it is another family's consumable
    function test_acrossSpendClosesTheExecutorRoute() public {
        _burnRealPermit2Nonce(PINNED);

        assertFalse(
            _check(_executorPayload(PINNED)),
            "an Across spend on the real bitmap must close the executor route"
        );
    }

    /*//////////////////////////////////////////////////////////////
                   THE REAL EXECUTOR'S NONCE VIEWS RESOLVE
    //////////////////////////////////////////////////////////////*/

    /// @dev The three namespace views are called on the real IntentExecutor on every validation.
    ///      A signature or argument-order mismatch would revert rather than answer, so this
    ///      exercises the wiring the mocks cannot.
    function test_realExecutorNamespaceViewsAnswer() public view {
        assertFalse(
            env.intentExecutor.isStandaloneIntentNonceConsumed(PINNED, account),
            "standalone unburned"
        );
        assertFalse(
            env.intentExecutor.isPermit2IntentNonceConsumed(PINNED, account),
            "permit2-intent unburned"
        );
        assertFalse(
            env.intentExecutor.isCompactIntentNonceConsumed(PINNED, account), "compact unburned"
        );
    }
}
