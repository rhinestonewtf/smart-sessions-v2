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
import { ValidateSignature } from "@compact-utils/executor/VerifySignature/VerifySignature.sol";

/// @title A nomination cannot carry a settlement whose own pre-claim never ran
/// @notice An executor settlement may call `consumeFor` and nominate a Permit2 nonce it does not
///         own. A Permit2 settlement on that nonce that skips its own burn is still refused: the
///         settling check also requires the executor to have consumed the nonce, which happens only
///         in the order's own pre-claim. And a `consumeFor` batch on the executor route can carry
///         nothing else (`RideSingleTx`), so the forged nomination is all that settlement does.
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

    /// @dev An executor settlement whose consume nominates SOMEONE ELSE'S settlement, alone or
    ///      with an execution X behind it
    function _settleViaExecutorNominating(
        uint256 executorNonce,
        uint256 forgedWitness,
        bool withX
    )
        internal
    {
        Execution[] memory calls = new Execution[](withX ? 2 : 1);
        calls[0] = Execution({
            target: address(oncePolicy),
            value: 0,
            callData: abi.encodeCall(IOneTimeUseIdPolicy.consumeFor, (ID, forgedWitness))
        });
        if (withX) {
            calls[1] = Execution({
                target: address(env.target),
                value: 0,
                callData: abi.encodeCall(MockTarget.targetFn, (42))
            });
        }

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

    /// @dev The ride, end to end. An executor settlement burns the id while nominating Permit2
    ///      nonce 4242, which it does not own. A Permit2 settlement on 4242 with a starved
    ///      pre-claim then tries to settle on that nomination. It is refused: its own pre-claim
    ///      never ran, so the executor never consumed nonce 4242. One burn, one settlement.
    function test_theExecutorRouteCannotNominateASettlementItDoesNotOwn() public {
        _enableSession(true);
        _useNonce(4242);

        _settleViaExecutorNominating({ executorNonce: 0, forgedWitness: 4242, withX: false });
        assertTrue(_burned(), "the executor settlement burned the id, once");

        bytes memory cd = _prepareStarved();

        vm.expectRevert();
        _claim(block.chainid, abi.encodePacked(env.solver.addr), cd);

        assertFalse(_nonceBurned(4242), "the ride is refused: no second spend");
    }

    /// @dev A registered op DOES run behind the executor-route `consumeFor` (burn-at-validation
    ///      bounds repetition, not batch content), but the forged nomination still buys nothing:
    /// the starved Permit2 settlement on that nonce is refused because its own pre-claim never
    ///      consumed the nonce. So the ride is: one executor use, one forged nomination that
    /// carries no Permit2 order.
    function test_theExecutorRouteRunsXButTheForgedNominationCarriesNothing() public {
        _enableSession(true);
        _useNonce(4242);

        _settleViaExecutorNominating({ executorNonce: 0, forgedWitness: 4242, withX: true });

        assertTrue(_burned(), "the executor settlement burned the id once");
        assertEq(env.target.param(), 42, "and the registered op ran - one session use");

        bytes memory cd = _prepareStarved();
        vm.expectRevert();
        _claim(block.chainid, abi.encodePacked(env.solver.addr), cd);

        assertFalse(_nonceBurned(4242), "the forged nomination carries no Permit2 order");
    }

    /// @dev The same attack with the witness NOT matching is refused, so the settlement above
    ///      really did ride the nomination rather than settle for some unrelated reason.
    function test_control_aNominationNamingAnotherSettlementIsNoHelp() public {
        _enableSession(true);
        _useNonce(4242);

        _settleViaExecutorNominating({ executorNonce: 0, forgedWitness: 9999, withX: false });
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

        assertEq(env.target.param(), 42, "the plain executor settlement executed");
        assertTrue(_burned(), "and burned");
    }
}
