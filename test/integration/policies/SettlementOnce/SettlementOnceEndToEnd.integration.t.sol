// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {
    SmartSessionEmissary_StandaloneExecutor_Integration_Test
} from "../../SmartSessionEmissary/SmartSessionEmissary_StandaloneExecutor.t.sol";

import { SettlementOncePolicy } from "@policies/once/SettlementOncePolicy.sol";

import { Execution } from "modulekit/integrations/ERC7579Exec.sol";
import { ActionData, PolicyData, Session, ERC7739Data } from "@types/DataTypes.sol";
import { PermissionId } from "@smartsessions/DataTypes.sol";
import { ISessionValidator } from "@smartsessions/interfaces/ISessionValidator.sol";
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";
import { SmartExecutionLib } from "@compact-utils/common/SmartExecutionLib.sol";
import {
    IStandaloneIntentExecutor
} from "@compact-utils/executor/interfaces/IStandaloneIntent.sol";
import { Paymaster } from "@compact-utils/executor/StandaloneIntent/aux/Paymaster.sol";
import { MockTarget } from "@rhinestone/compact-utils/src/tests/MockTarget.sol";

/// @title SettlementOncePolicy, end to end
/// @notice A REAL executor settlement, driven through the real `StandaloneIntentExecutor` and the
/// real `SmartSessionEmissary`, with `SettlementOncePolicy` installed as an action policy in the
/// position it will actually occupy.
///
/// The chain exercised here:
///
///   solver -> StandaloneIntentExecutor.executeSinglechainOpsWithGasRefund
///          -> _checkSigAndExecute (consumes the standalone nonce, then validates)
///          -> sigMode EMISSARY_EXECUTION -> emissary.verifyExecution
///          -> SmartSessionEmissary -> _enforceActionPolicies
///          -> SettlementOncePolicy.checkAction   <- the spend is burned here
///
/// The policy is installed on `Paymaster.callbackAllowMaxAmount`, which is the one action a
/// gas-refunded settlement is REQUIRED to perform exactly once — the executor's
/// `settleGasRefund_requireCallback` reads a single-use transient authorization, so a settlement
/// cannot omit it or repeat it. That is what satisfies the "exactly once per settlement"
/// install-time requirement this design carries.
contract SettlementOnceEndToEnd_Test is SmartSessionEmissary_StandaloneExecutor_Integration_Test {
    SettlementOncePolicy internal oncePolicy;

    uint256 internal constant PINNED = 4242;

    function setUp() public virtual override {
        super.setUp();

        // The REAL Permit2
        oncePolicy = new SettlementOncePolicy(ISignatureTransfer(address(env.permit2)));
    }

    /*//////////////////////////////////////////////////////////////
                                 HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev Same session shape as the parent's ArgPolicy setup, plus SettlementOncePolicy on the
    ///      paymaster callback. Action policies for one actionId are an AND, so ArgPolicy still
    ///      bounds WHAT the callback may do while this bounds HOW MANY TIMES it may happen.
    function _setupSessionWithOncePolicy() internal {
        vm.prank(env.smartAccount1.account);

        ActionData[] memory actions = new ActionData[](2);

        PolicyData[] memory targetPolicies = new PolicyData[](1);
        targetPolicies[0] =
            PolicyData({ policy: address(argPolicy), initData: _createTargetFnArgPolicyConfig() });
        actions[0] = ActionData({
            actionTarget: address(env.target),
            actionTargetSelector: MockTarget.targetFn.selector,
            actionPolicies: targetPolicies
        });

        PolicyData[] memory paymasterPolicies = new PolicyData[](2);
        paymasterPolicies[0] =
            PolicyData({ policy: address(argPolicy), initData: _createCallbackArgPolicyConfig() });
        paymasterPolicies[1] = PolicyData({
            policy: address(oncePolicy), initData: abi.encodePacked(bytes32(PINNED))
        });
        actions[1] = ActionData({
            actionTarget: address(paymaster),
            actionTargetSelector: Paymaster.callbackAllowMaxAmount.selector,
            actionPolicies: paymasterPolicies
        });

        PolicyData[] memory claimPolicies = new PolicyData[](1);
        claimPolicies[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });

        ERC7739Data memory erc7739Data;

        Session memory session = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: keccak256(abi.encodePacked("oncePolicyBatch", block.timestamp)),
            sessionValidatorInitData: "mockInitData",
            erc7739Policies: erc7739Data,
            actions: actions,
            claimPolicies: claimPolicies
        });

        Session[] memory sessions = new Session[](1);
        sessions[0] = session;
        PermissionId[] memory ids = smartSessionEmissary.enableSessions(sessions, bytes12(0));
        defaultPermissionId = ids[0];
    }

    /// @dev The batch a gas-refunded settlement performs: a call, then the mandatory paymaster
    ///      callback the once-policy is installed on
    function _settlementBatch() internal view returns (Execution[] memory executions) {
        executions = new Execution[](2);
        executions[0] = Execution({
            target: address(env.target),
            value: 0,
            callData: abi.encodeCall(MockTarget.targetFn, (TARGET_PARAM_VALUE))
        });
        executions[1] = Execution({
            target: address(paymaster),
            value: 0,
            callData: abi.encodeCall(Paymaster.callbackAllowMaxAmount, (GAS_TOKEN, MAX_GAS_REFUND))
        });
    }

    /// @dev Drives a real settlement through the real executor, on a CHOSEN executor nonce.
    ///      The parent helper hardcodes nonce 0, which means a second settlement is refused by
    ///      the executor's own `consumeNonce` before any policy is consulted — so a "second
    ///      settlement fails" test built on it proves nothing about the policy. Every settlement
    ///      here gets a fresh executor nonce, which is exactly the original exploit shape: the
    ///      signer mints a new digest per nonce and only the pin can bound it.
    function _settleWithExecutorNonce(uint256 executorNonce) internal {
        IStandaloneIntentExecutor.SingleChainOps memory signedOps =
            _buildSignedOps(_settlementBatch(), SmartExecutionLib.SigMode.EMISSARY_EXECUTION);
        signedOps.nonce = executorNonce;

        address solver = env.solver.addr;
        vm.prank(solver);
        env.intentExecutor
            .executeSinglechainOpsWithGasRefund(
                signedOps,
                IStandaloneIntentExecutor.GasRefund({
                    token: GAS_TOKEN, exchangeRate: EXCHANGE_RATE
                }),
                solver
            );
    }

    /*//////////////////////////////////////////////////////////////
                        ONE REAL SETTLEMENT, THEN NO MORE
    //////////////////////////////////////////////////////////////*/

    /// @dev The policy runs on the real emissary path and lets the first settlement through
    function test_firstRealSettlementSucceeds() public {
        _setupSessionWithOncePolicy();

        _settleWithExecutorNonce(0);

        assertEq(env.target.param(), TARGET_PARAM_VALUE, "the settlement executed");
        assertTrue(
            oncePolicy.isExecutorSpent(
                address(smartSessionEmissary), env.smartAccount1.account, PINNED
            ),
            "and the policy recorded the spend"
        );
    }

    /// @dev The property the whole design exists for, on real settlements: a second one is
    ///      refused EVEN ON A FRESH EXECUTOR NONCE. That qualifier is the whole test — with the
    ///      same nonce the executor would refuse it anyway and the policy would be untested.
    ///      `PolicyLib.callPolicy` reverts on VALIDATION_FAILED, so this surfaces as a revert.
    function test_secondRealSettlementOnAFreshNonceRefused() public {
        _setupSessionWithOncePolicy();

        _settleWithExecutorNonce(0);

        vm.expectRevert();
        _settleWithExecutorNonce(1);
    }

    /// @dev Ten more, the shape that produced eleven settlements from a session documented as one
    function test_noFurtherSettlementOnAnyNonce() public {
        _setupSessionWithOncePolicy();

        _settleWithExecutorNonce(0);

        for (uint256 i = 1; i <= 10; ++i) {
            vm.expectRevert();
            _settleWithExecutorNonce(i);
        }
    }

    /// @dev The control. Without the policy installed, the identical second settlement on a fresh
    ///      nonce goes straight through — so the refusal above is the policy's doing and not the
    ///      executor's. This test is what caught the first version of the test above passing for
    ///      the wrong reason.
    function test_withoutThePolicyASecondSettlementSucceeds() public {
        _setupSessionWithArgPolicies();

        _settleWithExecutorNonce(0);
        _settleWithExecutorNonce(1);

        assertEq(env.target.param(), TARGET_PARAM_VALUE, "both settlements executed");
    }
}
