// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { OneTimeUseIdE2E_Base } from "./OneTimeUseIdMatrixE2E.integration.t.sol";
import { IOneTimeUseIdPolicy } from "@policies/onetime/interfaces/IOneTimeUseIdPolicy.sol";
import { ActionData, PolicyData } from "@types/DataTypes.sol";
import { Execution } from "modulekit/integrations/ERC7579Exec.sol";
import { MockTarget } from "@rhinestone/compact-utils/src/tests/MockTarget.sol";
import { SmartExecutionLib } from "@compact-utils/common/SmartExecutionLib.sol";
import { Types } from "@compact-utils/types/OrderTypes.sol";
import { ICompactIntentExecutor } from "@compact-utils/executor/interfaces/ICompactIntent.sol";
import {
    IStandaloneIntentExecutor
} from "@compact-utils/executor/interfaces/IStandaloneIntent.sol";
import { ValidateSignature } from "@compact-utils/executor/VerifySignature/VerifySignature.sol";

/// @dev Runs a pre-claim and a standalone settlement in ONE external call, so they share a
///      transaction under `--isolate` as well.
contract TwoCallComposer {
    function run(
        address executor,
        address account,
        ICompactIntentExecutor.EIP712CompactStub calldata compactStub,
        ICompactIntentExecutor.EIP712ElementStubOrigin calldata elementStub,
        Types.Operation calldata preClaimOps,
        IStandaloneIntentExecutor.SingleChainOps calldata settlement,
        bytes calldata sig
    )
        external
        returns (bool sigOk, bool execOk)
    {
        (sigOk, execOk) = ICompactIntentExecutor(executor)
            .executePreClaimOpsWithCompactStub(account, compactStub, elementStub, preClaimOps, sig);
        IStandaloneIntentExecutor(executor).executeSinglechainOps(settlement);
    }
}

/// @title A burn validated in a transaction whose execution is skipped still spends the id
/// @notice The burn is written when `checkAction` validates it, so a batch that validates and then
///         fails at execution has spent the id all the same. Within the burning transaction a
///         no-burn batch is still admitted (one transaction of use, bounded by the session's action
///         policies); a later transaction finds the durable spend set and no marker, and is
/// refused.
abstract contract OneTimeUseIdSkippedExecution_Base is OneTimeUseIdE2E_Base {
    using SmartExecutionLib for *;

    /// @dev The batch needs a registered op that passes validation but reverts at execution, so
    ///      validation burns and execution fails. `MockTarget.reverting` is that op.
    function _extraActions(PolicyData[] memory actionPolicies)
        internal
        view
        override
        returns (ActionData[] memory extra)
    {
        extra = new ActionData[](1);
        extra[0] = ActionData({
            actionTarget: address(env.target),
            actionTargetSelector: MockTarget.reverting.selector,
            actionPolicies: actionPolicies
        });
    }

    /// @dev A batch that VALIDATES fully (the burn leads, then a registered op) but REVERTS at
    ///      execution.
    function _burnThenRevertingOps() internal view returns (Types.Operation memory) {
        Execution[] memory calls = new Execution[](2);
        calls[0] = Execution({
            target: address(oncePolicy),
            value: 0,
            callData: abi.encodeCall(IOneTimeUseIdPolicy.consume, (ID))
        });
        calls[1] = Execution({
            target: address(env.target),
            value: 0,
            callData: abi.encodeCall(MockTarget.reverting, ())
        });
        return SmartExecutionLib.SigMode.EMISSARY_EXECUTION.encode(calls);
    }

    function _noBurnSettlement(uint256 param)
        internal
        view
        returns (IStandaloneIntentExecutor.SingleChainOps memory signedOps)
    {
        Execution[] memory calls = new Execution[](1);
        calls[0] = Execution({
            target: address(env.target),
            value: 0,
            callData: abi.encodeCall(MockTarget.targetFn, (param))
        });
        signedOps.account = env.smartAccount1.account;
        signedOps.nonce = 0;
        signedOps.ops = SmartExecutionLib.SigMode.EMISSARY_EXECUTION.encode(calls);
        signedOps.signature = _emissarySig();
    }

    function _emptyElementStub()
        internal
        view
        returns (ICompactIntentExecutor.EIP712ElementStubOrigin memory)
    {
        return ICompactIntentExecutor.EIP712ElementStubOrigin({
            otherElements: new bytes32[](0),
            minGas: 0,
            elementOffset: 0,
            destOpsHash: bytes32(0),
            tokenInHash: bytes32(0),
            targetAttributesHash: bytes32(0),
            qHash: bytes32(0)
        });
    }

    /// @dev A pre-claim whose batch validates and then fails at execution. The entrypoint reports
    ///      both halves instead of reverting, so the burn written at validation stands.
    function _preClaimWithSkippedExecution(uint256 nonce)
        internal
        returns (bool sigOk, bool execOk)
    {
        vm.prank(makeAddr("relayer"));
        return ICompactIntentExecutor(address(env.intentExecutor))
            .executePreClaimOpsWithCompactStub(
                env.smartAccount1.account,
                ICompactIntentExecutor.EIP712CompactStub({
                    nonce: nonce, expires: block.timestamp + 1 days, notarizedChainId: block.chainid
                }),
                _emptyElementStub(),
                _burnThenRevertingOps(),
                _emissarySig()
            );
    }
}

contract OneTimeUseIdSkippedExecution_Test is OneTimeUseIdSkippedExecution_Base {
    using SmartExecutionLib for *;

    TwoCallComposer internal composer;

    function setUp() public override {
        super.setUp();
        _enableSession(true);
        composer = new TwoCallComposer();
    }

    /// @dev CONTROL: with no burn in this transaction, a no-burn settlement is refused.
    function test_control_noBurnSettlementIsRefusedWithoutABurn() public {
        vm.prank(env.solver.addr);
        vm.expectRevert(ValidateSignature.InvalidSignature.selector);
        env.intentExecutor.executeSinglechainOps(_noBurnSettlement(999));
        assertTrue(env.target.param() != 999, "nothing executed");
    }

    /// @dev The pre-claim burns at validation even though its execution fails; a no-burn
    ///      settlement in the SAME transaction rides the marker, which is the one transaction of
    ///      use the session has.
    function test_skippedExecution_burnsAndAdmitsANoBurnBatchOnlyInTheSameTx() public {
        (bool sigOk, bool execOk) = composer.run(
            address(env.intentExecutor),
            env.smartAccount1.account,
            ICompactIntentExecutor.EIP712CompactStub({
                nonce: 7777, expires: block.timestamp + 1 days, notarizedChainId: block.chainid
            }),
            _emptyElementStub(),
            _burnThenRevertingOps(),
            _noBurnSettlement(999),
            _emissarySig()
        );

        assertTrue(sigOk, "the pre-claim validated");
        assertFalse(execOk, "and its execution failed");
        assertTrue(_burned(), "yet the id is burned: validation, not execution, burned it");
        assertEq(env.target.param(), 999, "the no-burn batch ran in the same transaction (one use)");
    }

    /// @dev CONTROL: a pre-claim whose single burn executes burns too.
    function test_control_aPreClaimThatExecutesBurns() public {
        Execution[] memory calls = new Execution[](1);
        calls[0] = Execution({
            target: address(oncePolicy),
            value: 0,
            callData: abi.encodeCall(IOneTimeUseIdPolicy.consume, (ID))
        });
        Types.Operation memory ops = SmartExecutionLib.SigMode.EMISSARY_EXECUTION.encode(calls);

        vm.prank(makeAddr("relayer"));
        (bool sigOk, bool execOk) = ICompactIntentExecutor(address(env.intentExecutor))
            .executePreClaimOpsWithCompactStub(
                env.smartAccount1.account,
                ICompactIntentExecutor.EIP712CompactStub({
                    nonce: 8888, expires: block.timestamp + 1 days, notarizedChainId: block.chainid
                }),
                _emptyElementStub(),
                ops,
                _emissarySig()
            );

        assertTrue(sigOk, "validated");
        assertTrue(execOk, "and executed");
        assertTrue(_burned(), "the single-burn pre-claim burned the id");
    }
}

/// @title The transaction after a skipped execution
/// @notice The pre-claim runs in `setUp`, so every test body is a genuinely later transaction: the
///         transient marker is gone and only the durable spend remains.
contract OneTimeUseIdSkippedExecution_LaterTx_Test is OneTimeUseIdSkippedExecution_Base {
    function setUp() public override {
        super.setUp();
        _enableSession(true);

        (bool sigOk, bool execOk) = _preClaimWithSkippedExecution(7777);
        assertTrue(sigOk, "setUp: the pre-claim validated");
        assertFalse(execOk, "setUp: its execution failed");
    }

    function test_theFirstTransactionBurned() public view {
        assertTrue(_burned(), "the id is burned after the skipped execution");
    }

    function test_aNoBurnSettlementInALaterTransactionIsRefused() public {
        vm.prank(env.solver.addr);
        vm.expectRevert(ValidateSignature.InvalidSignature.selector);
        env.intentExecutor.executeSinglechainOps(_noBurnSettlement(999));

        assertTrue(env.target.param() != 999, "no marker survived the transaction boundary");
    }

    function test_aBurnLedSettlementInALaterTransactionIsRefused() public {
        vm.expectRevert(ValidateSignature.InvalidSignature.selector);
        _settleViaExecutor(0, 999);

        assertTrue(env.target.param() != 999, "the spent id refuses a second burn");
    }
}
