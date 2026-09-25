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
import { IWETH } from "@compact-utils/interfaces/IWETH.sol";

/// Hostile session key's own contract: settlement 1 (own-arbiter pre-claim) and settlement 2
/// (permissionless Router.routeClaim of order N) in ONE external call, so one transaction.
contract RideAttacker {
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

/// @title The single-transaction ride (RHI-5798), refused
/// @notice A session key runs a Permit2 pre-claim as its OWN arbiter through the permissionless
///         executor entrypoint, validated by `verifyExecution` only, so the arbiter pin on the
///         1271 list never runs. Its ops burn with `consumeFor(ID, N)` and execute X; that consumes
///         executor nonce N and leaves nomination N, so the real arbiter's settlement of order N
///         (whose own pre-claim fails on the used nonce, swallowed) passes the settling check in
/// the same transaction. One burn, two settlements - unless `checkAction` refuses X behind a
///         `consumeFor`, which is what these tests pin.
contract OneTimeUseIdRideSingleTx_Test is OneTimeUseIdE2E_Base {
    using SmartExecutionLib for *;

    uint256 internal constant NONCE = 4242;

    function _extraActions(PolicyData[] memory actionPolicies)
        internal
        view
        override
        returns (ActionData[] memory extra)
    {
        extra = new ActionData[](2);
        extra[0] = ActionData({
            actionTarget: address(oncePolicy),
            actionTargetSelector: IOneTimeUseIdPolicy.consumeFor.selector,
            actionPolicies: actionPolicies
        });
        extra[1] = ActionData({
            actionTarget: address(env.weth),
            actionTargetSelector: IWETH.deposit.selector,
            actionPolicies: actionPolicies
        });
    }

    function _nonceBurned(uint256 nonce) internal view returns (bool) {
        return (env.permit2.nonceBitmap($intent.sponsor, nonce >> 8) >> (nonce & 0xff)) & 1 == 1;
    }

    /// @dev The rogue pre-claim's ops: the burn nominating order N, then X
    function _rogueOps(bool withX) internal view returns (Types.Operation memory) {
        return _rogueOps(withX, false);
    }

    /// @dev The rogue pre-claim's ops: the burn nominating order N, optionally a wrap of the
    ///      account's whole native balance, optionally X
    function _rogueOps(bool withX, bool withWrap) internal view returns (Types.Operation memory) {
        Execution[] memory calls = new Execution[](1 + (withWrap ? 1 : 0) + (withX ? 1 : 0));
        calls[0] = Execution({
            target: address(oncePolicy),
            value: 0,
            callData: abi.encodeCall(IOneTimeUseIdPolicy.consumeFor, (ID, NONCE))
        });
        uint256 i = 1;
        if (withWrap) {
            calls[i++] = Execution({
                target: address(env.weth),
                value: env.smartAccount1.account.balance,
                callData: abi.encodeCall(IWETH.deposit, ())
            });
        }
        if (withX) {
            calls[i] = Execution({
                target: address(env.target),
                value: 0,
                callData: abi.encodeCall(MockTarget.targetFn, (777))
            });
        }
        return SmartExecutionLib.SigMode.EMISSARY_EXECUTION.encode(calls);
    }

    function _ride(Types.Operation memory ops, bytes memory cd) internal {
        RideAttacker(env.solver.addr)
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

    function setUp() public override {
        super.setUp();
        _enableSession(true);
        _useNonce(NONCE);

        // The solver EOA already holds tokenOut and the router approvals; give it the attacker's
        // code so ONE call from it is the whole attack (acts as the relayer AND the rogue arbiter).
        vm.etch(env.solver.addr, type(RideAttacker).runtimeCode);
    }

    /// @dev The regression: the rogue pre-claim is refused at validation, so it consumes no nonce,
    ///      burns nothing and executes nothing. The refusal is the executor's own, because
    ///      `verifyExecution` returned invalid for X behind the `consumeFor`.
    function test_singleTxRideByHostileSessionKeyContract_isRefused() public {
        bytes memory cd = _preparePermit2Settlement();

        vm.expectRevert(ValidateSignature.InvalidSignature.selector);
        _ride(_rogueOps(true), cd);

        assertFalse(_burned(), "nothing burned");
        assertTrue(MockTarget(address(env.target)).param() != 777, "X never executed");
        assertFalse(_nonceBurned(NONCE), "order N never settled");
        assertFalse(
            IPermit2IntentExecutor(address(env.intentExecutor))
                .isPermit2IntentNonceConsumed(NONCE, env.smartAccount1.account),
            "the executor nonce was not consumed"
        );
    }

    /// @dev CONTROL: the honest settlement of the same order N still lands after the refusal,
    ///      so the refusal above is the ride's, not the harness's.
    function test_control_honestSettlementOfOrderNStillLands() public {
        bytes memory cd = _preparePermit2Settlement();

        vm.expectRevert(ValidateSignature.InvalidSignature.selector);
        _ride(_rogueOps(true), cd);

        _claim(block.chainid, abi.encodePacked(env.solver.addr), cd);

        assertTrue(_burned(), "the honest pre-claim burned");
        assertTrue(_nonceBurned(NONCE), "and the honest settlement completed");
    }

    /// @dev A wrap behind the rogue burn is accepted and buys nothing: the account's native
    ///      becomes the account's WETH, order N pulls exactly what it signed, and everything else
    ///      is still refused. One settlement, one harmless asset-form change.
    function test_rideCarryingOnlyAWrap_yieldsExactlyOneSettlement() public {
        vm.deal(env.smartAccount1.account, 10 ether);
        bytes memory cd = _preparePermit2Settlement();

        _ride(_rogueOps(false, true), cd);

        assertTrue(_burned(), "the rogue pre-claim burned");
        assertTrue(_nonceBurned(NONCE), "order N settled once");
        assertEq(env.weth.balanceOf(env.smartAccount1.account), 10 ether, "the wrap ran");
        assertEq(env.smartAccount1.account.balance, 0, "out of the account's own native");
        assertTrue(MockTarget(address(env.target)).param() != 777, "nothing else executed");

        vm.expectRevert();
        _settleViaExecutor(0, 777);
        assertTrue(MockTarget(address(env.target)).param() != 777, "still nothing else");
    }

    /// @dev The wrap does not smuggle X in beside it.
    function test_rideCarryingAWrapAndX_isRefused() public {
        vm.deal(env.smartAccount1.account, 10 ether);
        bytes memory cd = _preparePermit2Settlement();

        vm.expectRevert(ValidateSignature.InvalidSignature.selector);
        _ride(_rogueOps(true, true), cd);

        assertFalse(_burned(), "nothing burned");
        assertEq(env.weth.balanceOf(env.smartAccount1.account), 0, "no wrap");
        assertTrue(MockTarget(address(env.target)).param() != 777, "X never executed");
        assertFalse(_nonceBurned(NONCE), "order N never settled");
    }

    /// @dev The accepted residual: a rogue pre-claim that ONLY burns still nominates order N, and
    ///      the real arbiter's settlement of N then lands. That is exactly ONE settlement - the one
    ///      the session signed for that arbiter - and the burn shuts every other route behind it.
    function test_burnOnlyRoguePreClaim_yieldsExactlyOneSettlement() public {
        bytes memory cd = _preparePermit2Settlement();

        _ride(_rogueOps(false), cd);

        assertTrue(_burned(), "the rogue pre-claim burned");
        assertTrue(_nonceBurned(NONCE), "order N settled once");
        assertTrue(MockTarget(address(env.target)).param() != 777, "nothing else executed");

        // Nothing rides behind it: the executor route is refused on the burned id...
        vm.expectRevert();
        _settleViaExecutor(0, 777);
        assertTrue(MockTarget(address(env.target)).param() != 777, "still nothing else");

        // ...and so is a second Permit2 order, whose nonce the nomination does not name.
        _useNonce(NONCE + 1);
        bytes memory second = _preparePermit2Settlement();
        vm.expectRevert();
        _claim(block.chainid, abi.encodePacked(env.solver.addr), second);
        assertFalse(_nonceBurned(NONCE + 1), "no second Permit2 settlement");
    }
}
