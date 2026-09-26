// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { OneTimeUseIdE2E_Base } from "./OneTimeUseIdMatrixE2E.integration.t.sol";
import { IOneTimeUseIdPolicy } from "@policies/onetime/interfaces/IOneTimeUseIdPolicy.sol";
import { ActionData, PolicyData } from "@types/DataTypes.sol";
import { Execution } from "modulekit/integrations/ERC7579Exec.sol";
import { SmartExecutionLib } from "@compact-utils/common/SmartExecutionLib.sol";
import { Paymaster } from "@compact-utils/executor/StandaloneIntent/aux/Paymaster.sol";
import {
    IStandaloneIntentExecutor
} from "@compact-utils/executor/interfaces/IStandaloneIntent.sol";

/// @dev The hostile session key's contract: N gas-refund executor calls in ONE external call, so
///      ONE transaction under `--isolate`. It is also the refund recipient (unsigned,
/// caller-chosen).
contract GasRefundAttacker {
    receive() external payable { }

    /// @notice A plain (no-refund) batch first, then refund calls: the one allowed callback may sit
    ///         in a later batch, but still only once per transaction.
    function runAfterPlain(
        address executor,
        IStandaloneIntentExecutor.SingleChainOps calldata plainBatch,
        IStandaloneIntentExecutor.SingleChainOps[] calldata refundBatches,
        uint256 packedOverhead
    )
        external
        returns (uint256 refunds)
    {
        IStandaloneIntentExecutor(executor).executeSinglechainOps(plainBatch);
        for (uint256 i; i < refundBatches.length; ++i) {
            IStandaloneIntentExecutor(executor)
                .executeSinglechainOpsWithGasRefund_ETH(
                    refundBatches[i], packedOverhead, address(this)
                );
            ++refunds;
        }
    }

    /// @return refunds How many of the N refund calls settled
    function run(
        address executor,
        IStandaloneIntentExecutor.SingleChainOps[] calldata batches,
        uint256 packedOverhead
    )
        external
        returns (uint256 refunds)
    {
        for (uint256 i; i < batches.length; ++i) {
            IStandaloneIntentExecutor(executor)
                .executeSinglechainOpsWithGasRefund_ETH(batches[i], packedOverhead, address(this));
            ++refunds;
        }
    }
}

/// @title H1 - the gas-refund path pays once PER EXECUTOR CALL, not once per transaction
/// @notice `Paymaster.callbackAllowMaxAmount` tstore-OVERWRITES the allowance and every
///         `execute*WithGasRefund_*` call settles one refund against it, to a recipient the CALLER
///         picks (unsigned). Under burn-at-validation the transient marker admits several executor
///         calls in the burning transaction, so N calls each carrying a refund callback pull N
///         refunds where the shipped design (burn must lead EVERY batch, burn at execution) allowed
///         one. The policy fix: at most ONE refund-callback op per (multiplexer, account, id) per
///         transaction, so the Paymaster's allowance is set at most once and a second refund call
///         fails its `require(maxAmount >= amount)`.
contract OneTimeUseIdGasRefundRide_Test is OneTimeUseIdE2E_Base {
    using SmartExecutionLib for *;

    /// @dev Per-call refund allowance the session key grants itself
    uint256 internal constant ALLOWANCE = 1 ether;

    /// @dev Signed by the session key: overhead in gas units (low 128) so that, at 1 wei gas
    ///      price, gasAmount = gasUsed + overhead ~ 0.5 ether <= ALLOWANCE; cap (high 128) = max.
    uint256 internal constant PACKED_OVERHEAD =
        (uint256(type(uint128).max) << 128) | uint256(0.5 ether);

    GasRefundAttacker internal attacker;

    /// @dev The refund callback is a registered action bounded only by the once-policy, i.e. a
    ///      per-call (not cumulative) bound - the precondition under which H1 bites.
    function _extraActions(PolicyData[] memory actionPolicies)
        internal
        view
        override
        returns (ActionData[] memory extra)
    {
        extra = new ActionData[](1);
        extra[0] = ActionData({
            actionTarget: address(env.paymaster),
            actionTargetSelector: Paymaster.callbackAllowMaxAmount.selector,
            actionPolicies: actionPolicies
        });
    }

    function setUp() public override {
        super.setUp();
        _enableSession(true);
        attacker = new GasRefundAttacker();
        vm.deal(env.smartAccount1.account, 100 ether);
        vm.txGasPrice(1);
    }

    function _callback() internal view returns (Execution memory) {
        return Execution({
            target: address(env.paymaster),
            value: ALLOWANCE,
            callData: abi.encodeCall(Paymaster.callbackAllowMaxAmount, (address(0), ALLOWANCE))
        });
    }

    function _burn() internal view returns (Execution memory) {
        return Execution({
            target: address(oncePolicy),
            value: 0,
            callData: abi.encodeCall(IOneTimeUseIdPolicy.consume, (ID))
        });
    }

    /// @dev Batch 0 leads with the burn and carries a refund callback; batches 1..n-1 carry only a
    ///      refund callback and ride the marker.
    function _refundBatches(uint256 n)
        internal
        view
        returns (IStandaloneIntentExecutor.SingleChainOps[] memory batches)
    {
        batches = new IStandaloneIntentExecutor.SingleChainOps[](n);
        for (uint256 i; i < n; ++i) {
            Execution[] memory calls = new Execution[](i == 0 ? 2 : 1);
            if (i == 0) {
                calls[0] = _burn();
                calls[1] = _callback();
            } else {
                calls[0] = _callback();
            }
            batches[i].account = env.smartAccount1.account;
            batches[i].nonce = i;
            batches[i].ops = SmartExecutionLib.SigMode.EMISSARY_EXECUTION.encode(calls);
            batches[i].signature = _emissarySig();
        }
    }

    /// @dev A nonzero tx gas price, so a refund has a nonzero amount. Under `--isolate` the
    /// isolated frame still sees `tx.gasprice == 0` and the payout is 0; the payout itself (~0.5
    /// ether
    ///      per call, ~1.5 ether for three on the unfixed policy) was recorded by the non-isolate
    ///      run in the report. The structural bound (how many calls settle) holds either way.
    modifier priced() {
        vm.txGasPrice(1);
        _;
    }

    /// @dev CONTROL: one refund call in the burning transaction settles exactly one refund of at
    ///      most the allowance. This is the honest gas-refund shape and must keep working.
    function test_control_oneRefundCallSettlesOnce() public priced {
        uint256 before = address(attacker).balance;

        uint256 refunds =
            attacker.run(address(env.intentExecutor), _refundBatches(1), PACKED_OVERHEAD);

        assertEq(refunds, 1, "one refund settled");
        assertLe(address(attacker).balance - before, ALLOWANCE, "bounded by the single allowance");
        assertTrue(_burned(), "the burn led");
    }

    /// @dev H1 CLOSED: the second refund call's callback op is refused at validation (one refund
    ///      callback per transaction), so the second executor call reverts and the whole attacker
    ///      call reverts. Exactly one refund per transaction. Before the fix, N calls pulled N
    ///      refunds (~1.5 ether for N = 3) to the caller-chosen recipient.
    function test_h1_nRefundCallsInOneTx_yieldAtMostOneRefund() public priced {
        uint256 before = address(attacker).balance;

        vm.expectRevert();
        attacker.run(address(env.intentExecutor), _refundBatches(3), PACKED_OVERHEAD);

        assertEq(address(attacker).balance - before, 0, "the reverted transaction paid nothing");
        assertFalse(_burned(), "and rolled back the burn with it");
    }

    function _callbackBatch(uint256 nonce)
        internal
        view
        returns (IStandaloneIntentExecutor.SingleChainOps memory b)
    {
        Execution[] memory cb = new Execution[](1);
        cb[0] = _callback();
        b.account = env.smartAccount1.account;
        b.nonce = nonce;
        b.ops = SmartExecutionLib.SigMode.EMISSARY_EXECUTION.encode(cb);
        b.signature = _emissarySig();
    }

    /// @dev The one allowed callback does not have to be in the burning batch: after a plain
    ///      burn-only batch, ONE later refund batch is admitted and a SECOND is refused at
    ///      validation, so the whole run reverts. Still one refund per transaction.
    function test_h1_refundCallbackInALaterBatch_isStillOnePerTx() public priced {
        Execution[] memory burnOnly = new Execution[](1);
        burnOnly[0] = _burn();
        IStandaloneIntentExecutor.SingleChainOps memory plain;
        plain.account = env.smartAccount1.account;
        plain.nonce = 0;
        plain.ops = SmartExecutionLib.SigMode.EMISSARY_EXECUTION.encode(burnOnly);
        plain.signature = _emissarySig();

        IStandaloneIntentExecutor.SingleChainOps[] memory one =
            new IStandaloneIntentExecutor.SingleChainOps[](1);
        one[0] = _callbackBatch(1);
        // Read-only probe: one later refund batch is admitted...
        uint256 snap = vm.snapshotState();
        uint256 refunds =
            attacker.runAfterPlain(address(env.intentExecutor), plain, one, PACKED_OVERHEAD);
        assertEq(refunds, 1, "one later refund batch is admitted");
        vm.revertToState(snap);

        // ...and two are not: the second callback is refused at validation.
        IStandaloneIntentExecutor.SingleChainOps[] memory two =
            new IStandaloneIntentExecutor.SingleChainOps[](2);
        two[0] = _callbackBatch(1);
        two[1] = _callbackBatch(2);
        vm.expectRevert();
        attacker.runAfterPlain(address(env.intentExecutor), plain, two, PACKED_OVERHEAD);
    }
}
