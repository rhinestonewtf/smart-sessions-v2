// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { OneTimeUseIdE2E_Base } from "./OneTimeUseIdMatrixE2E.integration.t.sol";
import { IOneTimeUseIdPolicy } from "@policies/onetime/interfaces/IOneTimeUseIdPolicy.sol";
import { ActionData, PolicyData } from "@types/DataTypes.sol";
import { Execution } from "modulekit/integrations/ERC7579Exec.sol";
import { MockTarget } from "@rhinestone/compact-utils/src/tests/MockTarget.sol";
import { SmartExecutionLib } from "@compact-utils/common/SmartExecutionLib.sol";
import { Types } from "@compact-utils/types/OrderTypes.sol";
import { IPermit2IntentExecutor } from "@compact-utils/executor/interfaces/IPermit2Intent.sol";
import { ValidateSignature } from "@compact-utils/executor/VerifySignature/VerifySignature.sol";

/// @dev Runs a Permit2 pre-claim and then a routed claim in ONE external call, so they share a
///      transaction under `--isolate` as well. The claim's revert is bubbled.
contract PreClaimAndClaimComposer {
    function run(
        address executor,
        address account,
        IPermit2IntentExecutor.EIP712Permit2Stub calldata stub,
        IPermit2IntentExecutor.EIP712Permit2MandateStub calldata mstub,
        Types.Operation calldata ops,
        bytes calldata sig,
        address router,
        bytes calldata relayerContext,
        bytes calldata adapterCalldata
    )
        external
    {
        IPermit2IntentExecutor(executor)
            .executePreClaimOpsWithPermit2Stub(account, stub, mstub, ops, sig);
        (bool ok, bytes memory ret) = router.call(
            abi.encodeWithSignature("routeClaim(bytes,bytes)", relayerContext, adapterCalldata)
        );
        if (!ok) {
            assembly {
                revert(add(ret, 0x20), mload(ret))
            }
        }
    }
}

/// @title A pre-claim and the settlement it nominates, in one transaction
/// @notice A Permit2 pre-claim validated through `verifyExecution` burns with `consumeFor(ID, N)`
///         and nominates order N; a registered op behind the burn runs. The arbiter's settlement of
///         order N in the SAME transaction then passes the settling check. That is exactly one
///         transaction and one Permit2 order: a second order in the transaction is refused, and so
///         is any later transaction (`OneTimeUseIdOwnArbiterSameTx_LaterTx_Test`).
abstract contract OneTimeUseIdOwnArbiterSameTx_Base is OneTimeUseIdE2E_Base {
    using SmartExecutionLib for *;

    uint256 internal constant NONCE = 4242;

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

    /// @dev The pre-claim's ops: the burn nominating order N, optionally a registered op X
    function _preClaimOps(bool withX) internal view returns (Types.Operation memory) {
        Execution[] memory calls = new Execution[](withX ? 2 : 1);
        calls[0] = Execution({
            target: address(oncePolicy),
            value: 0,
            callData: abi.encodeCall(IOneTimeUseIdPolicy.consumeFor, (ID, NONCE))
        });
        if (withX) {
            calls[1] = Execution({
                target: address(env.target),
                value: 0,
                callData: abi.encodeCall(MockTarget.targetFn, (777))
            });
        }
        return SmartExecutionLib.SigMode.EMISSARY_EXECUTION.encode(calls);
    }

    /// @dev A pre-claim nominating TWO Permit2 orders in one batch
    function _preClaimOpsTwoOrders() internal view returns (Types.Operation memory) {
        Execution[] memory calls = new Execution[](2);
        calls[0] = Execution({
            target: address(oncePolicy),
            value: 0,
            callData: abi.encodeCall(IOneTimeUseIdPolicy.consumeFor, (ID, NONCE))
        });
        calls[1] = Execution({
            target: address(oncePolicy),
            value: 0,
            callData: abi.encodeCall(IOneTimeUseIdPolicy.consumeFor, (ID, NONCE + 1))
        });
        return SmartExecutionLib.SigMode.EMISSARY_EXECUTION.encode(calls);
    }

    /// @dev The pre-claim and the claim of order N, from the solver, in one call
    function _preClaimThenClaim(Types.Operation memory ops, bytes memory cd) internal {
        PreClaimAndClaimComposer(env.solver.addr)
            .run(
                address(env.intentExecutor),
                env.smartAccount1.account,
                IPermit2IntentExecutor.EIP712Permit2Stub(NONCE, block.timestamp + 1 days),
                IPermit2IntentExecutor.EIP712Permit2MandateStub(
                    bytes32(0), 0, bytes32(0), bytes32(0), bytes32(0)
                ),
                ops,
                _emissarySig(),
                address(env.router),
                abi.encodePacked(env.solver.addr),
                cd
            );
    }

    function setUp() public virtual override {
        super.setUp();
        _enableSession(true);
        _useNonce(NONCE);

        // The solver EOA already holds tokenOut and the router approvals; give it the composer's
        // code so ONE call from it runs both halves.
        vm.etch(env.solver.addr, type(PreClaimAndClaimComposer).runtimeCode);
    }
}

contract OneTimeUseIdOwnArbiterSameTx_Test is OneTimeUseIdOwnArbiterSameTx_Base {
    /// @dev The pre-claim burns, its registered X executes, and order N settles: one transaction,
    ///      one Permit2 order. X is no more than the session key could run in any single use;
    ///      order N is the settlement the session signed. A second Permit2 order is refused.
    function test_preClaimAndSettlement_yieldOneTransactionOneOrder() public {
        bytes memory cd = _preparePermit2Settlement();

        _preClaimThenClaim(_preClaimOps(true), cd);

        assertTrue(_burned(), "the pre-claim burned");
        assertTrue(_nonceBurned(NONCE), "order N settled once");
        assertEq(MockTarget(address(env.target)).param(), 777, "X ran - one session use");

        // A second Permit2 order is refused: its pre-claim's burn hits the durable spend.
        _useNonce(NONCE + 1);
        bytes memory second = _preparePermit2Settlement();
        vm.expectRevert();
        _claim(block.chainid, abi.encodePacked(env.solver.addr), second);
        assertFalse(_nonceBurned(NONCE + 1), "no second Permit2 order");
    }

    /// @dev A SECOND `consumeFor` in the batch - a second Permit2 order in one transaction - is
    ///      refused at validation: the second burn hits the durable spend the first just set, so
    ///      the whole pre-claim validates FALSE, rolls back the first burn, and nothing settles.
    function test_secondOrderInTheSameTransaction_isRefused() public {
        bytes memory cd = _preparePermit2Settlement();

        vm.expectRevert(ValidateSignature.InvalidSignature.selector);
        _preClaimThenClaim(_preClaimOpsTwoOrders(), cd);

        assertFalse(_burned(), "the rolled-back burn spent nothing");
        assertFalse(_nonceBurned(NONCE), "no order settled");
    }

    /// @dev CONTROL: order N settles honestly on its own, so the "no second order" refusals are
    ///      the single-use guarantee, not the harness being unable to settle N.
    function test_control_honestSettlementOfOrderNLands() public {
        bytes memory cd = _preparePermit2Settlement();

        _claim(block.chainid, abi.encodePacked(env.solver.addr), cd);

        assertTrue(_burned(), "the honest pre-claim burned");
        assertTrue(_nonceBurned(NONCE), "and the honest settlement completed");
    }

    /// @dev A pre-claim that ONLY burns still nominates order N, and the settlement of N lands.
    ///      That is exactly ONE settlement - the one the session signed for that arbiter. In the
    ///      same transaction a second burn-led settlement and a second Permit2 order are refused:
    ///      the id is spent.
    function test_burnOnlyPreClaim_yieldsExactlyOneSettlement() public {
        bytes memory cd = _preparePermit2Settlement();

        _preClaimThenClaim(_preClaimOps(false), cd);

        assertTrue(_burned(), "the pre-claim burned");
        assertTrue(_nonceBurned(NONCE), "order N settled once");
        assertTrue(MockTarget(address(env.target)).param() != 777, "nothing else executed");

        vm.expectRevert(ValidateSignature.InvalidSignature.selector);
        _settleViaExecutor(0, 777);
        assertTrue(MockTarget(address(env.target)).param() != 777, "a second burn is refused");

        _useNonce(NONCE + 1);
        bytes memory second = _preparePermit2Settlement();
        vm.expectRevert();
        _claim(block.chainid, abi.encodePacked(env.solver.addr), second);
        assertFalse(_nonceBurned(NONCE + 1), "no second Permit2 settlement");
    }
}

/// @title The transaction after the pre-claim and its settlement
/// @notice Both halves run in `setUp`, so every test body is a genuinely later transaction: the
///         transient marker is gone and only the durable spend remains, so a settlement with or
///         without a burn is refused.
contract OneTimeUseIdOwnArbiterSameTx_LaterTx_Test is OneTimeUseIdOwnArbiterSameTx_Base {
    function setUp() public override {
        super.setUp();
        _preClaimThenClaim(_preClaimOps(true), _preparePermit2Settlement());

        // The settlement spent order N and the sponsor's whole tokenIn. Restore both so the
        // inherited Permit2ClaimPolicy tests, which reuse this fixture, still have an order.
        _useNonce(NONCE + 1);
        env.token1.mint($intent.sponsor, 100 ether);
        vm.prank($intent.sponsor);
        env.token1.approve(address(env.permit2), 100 ether);
    }

    function test_theFirstTransactionSettledOnce() public view {
        assertTrue(_burned(), "the pre-claim burned");
        assertTrue(_nonceBurned(NONCE), "order N settled");
        assertEq(MockTarget(address(env.target)).param(), 777, "X ran");
    }

    function test_aNoBurnSettlementInALaterTransactionIsRefused() public {
        vm.expectRevert(ValidateSignature.InvalidSignature.selector);
        _settleViaExecutorWithoutConsume(0, 555);

        assertTrue(MockTarget(address(env.target)).param() != 555, "no marker crossed the boundary");
    }

    function test_aBurnLedSettlementInALaterTransactionIsRefused() public {
        vm.expectRevert(ValidateSignature.InvalidSignature.selector);
        _settleViaExecutor(0, 555);

        assertTrue(MockTarget(address(env.target)).param() != 555, "the spent id refuses a burn");
    }
}
