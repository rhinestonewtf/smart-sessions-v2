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
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { IWETH } from "@compact-utils/interfaces/IWETH.sol";

/// @title A Permit2 pre-claim validated through `verifyExecution` burns with `consumeFor`
/// @notice A Permit2 pre-claim carries an execution-emissary sigMode (the SDK forces it for
///         one-time-use sessions), so its `consumeFor` reaches `checkAction`, which burns and
///         nominates the order. The rest of the batch is bounded by the session's own action
///         policies, not by this one: a registered op behind the burn runs, an unregistered one is
///         refused by SmartSessions before any policy sees it.
contract OneTimeUseIdPreClaimVerifyExecution_Test is OneTimeUseIdE2E_Base {
    using SmartExecutionLib for *;

    /// @dev The pre-claim's `consumeFor` needs an action entry, as a real session's fallback
    ///      action provides; the once-policy sits on it, so it runs through `checkAction`. The
    ///      approve and wrap entries stand in for the same fallback covering the tokenIn.
    function _extraActions(PolicyData[] memory actionPolicies)
        internal
        view
        override
        returns (ActionData[] memory extra)
    {
        extra = new ActionData[](4);
        extra[0] = ActionData({
            actionTarget: address(oncePolicy),
            actionTargetSelector: IOneTimeUseIdPolicy.consumeFor.selector,
            actionPolicies: actionPolicies
        });
        extra[1] = ActionData({
            actionTarget: address(env.token1),
            actionTargetSelector: IERC20.approve.selector,
            actionPolicies: actionPolicies
        });
        extra[2] = ActionData({
            actionTarget: address(env.weth),
            actionTargetSelector: IWETH.deposit.selector,
            actionPolicies: actionPolicies
        });
        extra[3] = ActionData({
            actionTarget: address(env.target),
            actionTargetSelector: MockTarget.reverting.selector,
            actionPolicies: actionPolicies
        });
    }

    function _wrap(uint256 amount) internal view returns (Execution memory) {
        return Execution({
            target: address(env.weth), value: amount, callData: abi.encodeCall(IWETH.deposit, ())
        });
    }

    function _nonceBurned(uint256 nonce) internal view returns (bool) {
        return (env.permit2.nonceBitmap($intent.sponsor, nonce >> 8) >> (nonce & 0xff)) & 1 == 1;
    }

    /// @dev Pure EMISSARY_EXECUTION (no ERC-1271 fallback), so the pre-claim is validated only by
    ///      `verifyExecution` and a `checkAction` refusal cannot be routed around.
    function _injectViaVerifyExecution(Execution[] memory extra) internal {
        Execution[] memory ops = new Execution[](1 + extra.length);
        ops[0] = Execution({
            target: address(oncePolicy),
            value: 0,
            callData: abi.encodeCall(IOneTimeUseIdPolicy.consumeFor, (ID, $intent.nonce))
        });
        for (uint256 i; i < extra.length; ++i) {
            ops[1 + i] = extra[i];
        }
        $intent.element.mandate.originOps = SmartExecutionLib.SigMode.EMISSARY_EXECUTION.encode(ops);
        $intent.permit2Hash =
            hashPermit2($intent.sponsor, $intent.nonce, $intent.expires, arbiter, $intent.element);
        $intent.digest = _hashTypedDataPermit2(block.chainid, $intent.permit2Hash);
    }

    function _settlementCalldata() internal returns (bytes memory) {
        Types.Order memory order = _getPermit2Order();
        $intent.userEmissarySig = _createSmartSessionSignature(_createPolicyData());
        return abi.encodeCall(
            MockAdapter.mock_permit2_handleClaim,
            (MockAdapter.ClaimDataPermit2({
                    order: order,
                    userSigs: Types.Signatures({
                        notarizedClaimSig: $intent.userEmissarySig, preClaimSig: _emissarySig()
                    })
                }))
        );
    }

    function _approve(address spender) internal view returns (Execution memory) {
        return Execution({
            target: address(env.token1),
            value: 0,
            callData: abi.encodeCall(IERC20.approve, (spender, type(uint256).max))
        });
    }

    function _targetFn(uint256 param) internal view returns (Execution memory) {
        return Execution({
            target: address(env.target),
            value: 0,
            callData: abi.encodeCall(MockTarget.targetFn, (param))
        });
    }

    function test_permit2PreClaimThroughVerifyExecution_settlesAndBurns() public {
        _enableSession(true);
        _injectViaVerifyExecution(new Execution[](0));

        _claim(block.chainid, abi.encodePacked(env.solver.addr), _settlementCalldata());

        assertTrue(_burned(), "the pre-claim consumeFor burned the id");
        assertTrue(_nonceBurned($intent.nonce), "and the Permit2 settlement completed");
    }

    /// @dev The batch the orchestrator signs: the burn, then `approve(PERMIT2)`.
    function test_permit2PreClaimWithPermit2Approval_settlesAndBurns() public {
        _enableSession(true);
        Execution[] memory extra = new Execution[](1);
        extra[0] = _approve(address(env.permit2));
        _injectViaVerifyExecution(extra);

        _claim(block.chainid, abi.encodePacked(env.solver.addr), _settlementCalldata());

        assertTrue(_burned(), "the pre-claim burned");
        assertTrue(_nonceBurned($intent.nonce), "the Permit2 settlement completed");
        assertEq(
            env.token1.allowance($intent.sponsor, address(env.permit2)),
            type(uint256).max,
            "and the approval ran"
        );
    }

    /// @dev A pre-claim carrying a wrap of the account's own native, an approval and a user op
    ///      behind the burn: every registered op rides the burn and the order settles once. A
    ///      second Permit2 order in the same transaction is refused.
    function test_permit2PreClaimCarryingAWrapAnApprovalAndAUserOp_settlesOnce() public {
        _enableSession(true);
        vm.deal($intent.sponsor, 10 ether);
        Execution[] memory extra = new Execution[](3);
        extra[0] = _wrap(3 ether);
        extra[1] = _approve(address(env.permit2));
        extra[2] = _targetFn(777);
        _injectViaVerifyExecution(extra);

        _claim(block.chainid, abi.encodePacked(env.solver.addr), _settlementCalldata());

        assertTrue(_burned(), "the pre-claim burned");
        assertTrue(_nonceBurned($intent.nonce), "the Permit2 settlement completed");
        assertEq(env.weth.balanceOf($intent.sponsor), 3 ether, "the wrap ran, into the account");
        assertEq($intent.sponsor.balance, 7 ether, "out of the account's own native");
        assertEq(
            env.token1.allowance($intent.sponsor, address(env.permit2)),
            type(uint256).max,
            "the approval ran"
        );
        assertEq(MockTarget(address(env.target)).param(), 777, "and the user op ran");

        uint256 second = $intent.nonce + 1;
        _useNonce(second);
        _injectViaVerifyExecution(new Execution[](0));
        bytes memory cd = _settlementCalldata();
        vm.expectRevert();
        _claim(block.chainid, abi.encodePacked(env.solver.addr), cd);
        assertFalse(_nonceBurned(second), "no second Permit2 order");
    }

    /// @dev A REGISTERED op behind the `consumeFor` runs: burn-at-validation bounds repetition
    ///      (one tx, one order), not batch content, so `targetFn` rides the burn and the settlement
    ///      completes. This is no more than the session key could do in any single use; the
    ///      session's OWN action policy on `targetFn` is what bounds its content.
    ///      `OwnArbiterSameTx` proves it yields no second order and no later transaction.
    function test_permit2PreClaimWithARegisteredOp_settles() public {
        _enableSession(true);
        Execution[] memory extra = new Execution[](1);
        extra[0] = _targetFn(777);
        _injectViaVerifyExecution(extra);

        _claim(block.chainid, abi.encodePacked(env.solver.addr), _settlementCalldata());

        assertTrue(_burned(), "the pre-claim burned");
        assertTrue(_nonceBurned($intent.nonce), "the Permit2 settlement completed once");
        assertEq(MockTarget(address(env.target)).param(), 777, "and the registered op ran");
    }

    /// @dev CONTROL (SmartSessions action lookup, not this policy): an UNREGISTERED op behind the
    ///      `consumeFor` is refused by SmartSessions before any policy runs. That reverts the
    ///      validation, which rolls back the burn, so nothing settles. The session's action list
    ///      bounds WHAT may run; the once-policy never sees the op.
    function test_control_smartSessionsRefusesAnUnregisteredOpBehindTheBurn() public {
        _enableSession(true);
        Execution[] memory extra = new Execution[](1);
        extra[0] = Execution({
            target: makeAddr("unregisteredTarget"),
            value: 0,
            callData: abi.encodeCall(MockTarget.targetFn, (777))
        });
        _injectViaVerifyExecution(extra);
        bytes memory cd = _settlementCalldata();

        vm.expectRevert();
        _claim(block.chainid, abi.encodePacked(env.solver.addr), cd);

        assertFalse(_burned(), "the reverting validation rolled back the burn");
        assertFalse(_nonceBurned($intent.nonce), "nothing settled");
    }

    /// @dev An HONEST pre-claim through the arbiter whose batch validates but REVERTS at execution
    ///      (a registered op that reverts, after the burn). The Permit2 executor bubbles the
    ///      revert, so the whole executor frame - validation-time burn included - rolls back, and
    ///      the unlock then fails (no consumed nonce, no nomination). The id is UNBURNED and the
    ///      session is retryable: the same order settles once the reverting op is dropped.
    function test_permit2PreClaimWhoseBatchReverts_rollsBackTheBurn_andIsRetryable() public {
        _enableSession(true);
        Execution[] memory extra = new Execution[](1);
        extra[0] = Execution({
            target: address(env.target),
            value: 0,
            callData: abi.encodeCall(MockTarget.reverting, ())
        });
        _injectViaVerifyExecution(extra);
        bytes memory cd = _settlementCalldata();

        vm.expectRevert();
        _claim(block.chainid, abi.encodePacked(env.solver.addr), cd);

        assertFalse(_burned(), "the executor revert rolled the burn back");
        assertFalse(_nonceBurned($intent.nonce), "nothing settled");

        // Retry: the honest pre-claim without the reverting op settles on the same nonce.
        _injectViaVerifyExecution(new Execution[](0));
        _claim(block.chainid, abi.encodePacked(env.solver.addr), _settlementCalldata());

        assertTrue(_burned(), "the retry burned");
        assertTrue(_nonceBurned($intent.nonce), "and settled");
    }

    /// @dev A registered `approve` runs behind the `consumeFor` for the same reason. The
    /// once-policy does NOT restrict the spender - the session's own policy on `approve` does. Here
    /// the
    ///      session registers `token1.approve` with only the once-policy, so it admits any spender:
    ///      exactly the power the key already has in a plain single-use batch.
    function test_permit2PreClaimApprovingAnotherSpender_settlesBecauseApproveIsRegistered()
        public
    {
        _enableSession(true);
        Execution[] memory extra = new Execution[](1);
        extra[0] = _approve(makeAddr("otherSpender"));
        _injectViaVerifyExecution(extra);

        _claim(block.chainid, abi.encodePacked(env.solver.addr), _settlementCalldata());

        assertTrue(_burned(), "the pre-claim burned");
        assertTrue(_nonceBurned($intent.nonce), "the Permit2 settlement completed once");
        assertEq(
            env.token1.allowance($intent.sponsor, makeAddr("otherSpender")),
            type(uint256).max,
            "the registered approve ran - bounded by the approve action policy, not the once-policy"
        );
    }
}
