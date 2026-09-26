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

/// @dev The hostile session key's contract: a Compact pre-claim (swallowed) and a no-burn
///      standalone settlement in ONE external call, so ONE transaction even under `--isolate`.
contract CompactSwallowAttacker {
    function run(
        address executor,
        address account,
        ICompactIntentExecutor.EIP712CompactStub calldata compactStub,
        ICompactIntentExecutor.EIP712ElementStubOrigin calldata elementStub,
        Types.Operation calldata swallowedBurnOps,
        IStandaloneIntentExecutor.SingleChainOps calldata noBurnSettlement,
        bytes calldata sig
    )
        external
        returns (bool sigOk, bool execOk)
    {
        (sigOk, execOk) = ICompactIntentExecutor(executor)
            .executePreClaimOpsWithCompactStub(
                account, compactStub, elementStub, swallowedBurnOps, sig
            );
        IStandaloneIntentExecutor(executor).executeSinglechainOps(noBurnSettlement);
    }
}

/// @title Finding 2 - the Compact pre-claim swallow, closed by burn at validation
/// @notice `executePreClaimOpsWithCompactStub` (permissionless) validates the batch through the
///         emissary (`verifyExecution` -> `checkAction`), consumes the nonce, then runs
///         `tryExecuteOps`, which does NOT revert on failure. On the SHIPPED policy the burn lived
///         at execution, so a batch that validated but reverted at execution left the transient
///         flag set with the id UNBURNED, and a later no-burn batch rode it - unbounded uses.
///
///         Burn at validation closes it: `checkAction` writes the DURABLE spend when it validates
///         the burn op, BEFORE `tryExecuteOps` runs, so the swallowed revert cannot roll it back.
///         The id is burned after the swallowed pre-claim. A no-burn batch may still ride the
///         transient marker WITHIN THE SAME TRANSACTION (that is one transaction of use, bounded by
///         the session's action policies), but a LATER transaction finds the durable spend set and
///         no marker, and is refused. One transaction, not unbounded uses.
contract OneTimeUseIdCompactSwallowRide_Test is OneTimeUseIdE2E_Base {
    using SmartExecutionLib for *;

    CompactSwallowAttacker internal attacker;

    /// @dev The swallowed batch needs a registered op that reverts at EXECUTION but passes
    ///      validation, so validation burns and the execution is swallowed. `MockTarget.reverting`
    ///      is that op.
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

    function setUp() public override {
        super.setUp();
        _enableSession(true);
        attacker = new CompactSwallowAttacker();
    }

    /// @dev A batch that VALIDATES fully (the burn leads, then a registered op) but REVERTS at
    ///      execution, so the arbiter's `tryExecuteOps` swallows it while the validation-time burn
    ///      stands.
    function _swallowedBurnOps() internal view returns (Types.Operation memory) {
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

    function _swallowedPreClaim(uint256 nonce) internal returns (bool sigOk, bool execOk) {
        return ICompactIntentExecutor(address(env.intentExecutor))
            .executePreClaimOpsWithCompactStub(
                env.smartAccount1.account,
                ICompactIntentExecutor.EIP712CompactStub({
                    nonce: nonce, expires: block.timestamp + 1 days, notarizedChainId: block.chainid
                }),
                _emptyElementStub(),
                _swallowedBurnOps(),
                _emissarySig()
            );
    }

    /// @dev CONTROL: with no burn in this transaction, a no-burn settlement is refused. This is the
    ///      guarantee finding 2 broke and burn-at-validation restores across transactions.
    function test_control_noBurnSettlementIsRefusedWithoutABurn() public {
        vm.prank(env.solver.addr);
        vm.expectRevert();
        env.intentExecutor.executeSinglechainOps(_noBurnSettlement(999));
        assertTrue(env.target.param() != 999, "nothing executed");
    }

    /// @dev The swallowed pre-claim BURNS the id at validation (it cannot be rolled back by the
    ///      swallowed execution). A no-burn settlement in the SAME transaction then rides the
    ///      transient marker - which is one transaction of use, all the key ever had. The shipped
    ///      design left the id UNBURNED here and rode across transactions.
    function test_poc_swallowedPreClaimBurnsAndXRidesOnlyInTheSameTx() public {
        (bool sigOk, bool execOk) = attacker.run(
            address(env.intentExecutor),
            env.smartAccount1.account,
            ICompactIntentExecutor.EIP712CompactStub({
                nonce: 7777, expires: block.timestamp + 1 days, notarizedChainId: block.chainid
            }),
            _emptyElementStub(),
            _swallowedBurnOps(),
            _noBurnSettlement(999),
            _emissarySig()
        );

        assertTrue(sigOk, "the pre-claim validated");
        assertFalse(execOk, "and its execution was swallowed");
        assertTrue(_burned(), "yet the id is burned - validation, not execution, burned it");
        assertEq(env.target.param(), 999, "the no-burn batch ran in the SAME transaction (one use)");
    }

    /// @dev The leaked marker does NOT cross a transaction boundary. The swallowed pre-claim burns
    ///      the id in one transaction; a no-burn settlement in a LATER transaction (a separate
    ///      top-level call under `--isolate`) is refused - the durable spend is set and no marker
    ///      survives. This is the unbounded-uses ride, closed.
    function test_theSwallowedFlagDoesNotRideIntoALaterTransaction() public {
        (bool sigOk, bool execOk) = _swallowedPreClaim(7777);

        assertTrue(sigOk, "the pre-claim validated");
        assertFalse(execOk, "its execution was swallowed");
        assertTrue(_burned(), "and the id is burned after the swallowed pre-claim");

        // A separate top-level call = a later transaction under --isolate.
        vm.prank(env.solver.addr);
        vm.expectRevert();
        env.intentExecutor.executeSinglechainOps(_noBurnSettlement(999));

        assertTrue(env.target.param() != 999, "no no-burn settlement rode into a later transaction");
    }

    /// @dev A legitimate Compact pre-claim (a single burn that executes) still settles.
    function test_control_honestCompactPreClaimStillBurns() public {
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
        assertTrue(_burned(), "the honest single-burn pre-claim burned the id");
    }
}
