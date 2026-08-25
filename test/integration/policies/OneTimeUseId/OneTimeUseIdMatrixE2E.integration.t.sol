// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {
    Permit2ClaimPolicy_Integration_Test
} from "../Permit2ClaimPolicy/Permit2ClaimPolicy.integration.t.sol";

import { MockAdapter } from "@mocks/MockAdapter.sol";
import { ModuleKitHelpers } from "@modulekit/ModuleKit.sol";
import { OneTimeUseIdPolicy } from "@policies/onetime/OneTimeUseIdPolicy.sol";
import { IOneTimeUseIdPolicy } from "@policies/onetime/interfaces/IOneTimeUseIdPolicy.sol";
import { SmartSessionEmissaryMock } from "@mocks/SmartSessionEmissaryMock.sol";

import { Execution } from "modulekit/integrations/ERC7579Exec.sol";
import { MockTarget } from "@rhinestone/compact-utils/src/tests/MockTarget.sol";
import { Session } from "@types/DataTypes.sol";
import {
    PolicyData,
    ActionData,
    ERC7739Data,
    ERC7739Context,
    PermissionId,
    SmartSessionMode
} from "@smartsessions/DataTypes.sol";
import { ISessionValidator } from "@smartsessions/interfaces/ISessionValidator.sol";
import { MODULE_TYPE_VALIDATOR } from "@modulekit/accounts/common/interfaces/IERC7579Module.sol";
import { SmartExecutionLib } from "@compact-utils/common/SmartExecutionLib.sol";
import { TestHelperLib } from "@compact-utils/tests/Environment.sol";
import { Types } from "@compact-utils/types/OrderTypes.sol";
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";
import {
    IStandaloneIntentExecutor
} from "@compact-utils/executor/interfaces/IStandaloneIntent.sol";
import { FIELD_ARBITER, MODE_CHECK_STORAGE } from "@policies/claim/base/types/BaseDataTypes.sol";

/// @title OneTimeUseIdPolicy — the E2E harness
/// @notice Both routes settle for real. The policy sits on BOTH surfaces and neither of them
///         knows anything about a settlement layer:
///
///   Permit2   router -> arbiter -> _permit2PreClaimOps
///                       |- isValidSignature          -> check1271SignedAction  (read)
///                       `- executeOps(preClaimOps)   -> consume                (BURN)
///                     -> _unlockPermit2 -> Permit2.permitWitnessTransferFrom
///                       `- account.isValidSignature  -> check1271SignedAction  (read, tolerated)
///
///   executor  solver -> StandaloneIntentExecutor.executeSinglechainOps
///                     -> sigMode EMISSARY_EXECUTION -> emissary.verifyExecution
///                       |- _enforceActionPolicies    -> checkAction            (read)
///                       `- executeOps                -> consume                (BURN)
abstract contract OneTimeUseIdE2E_Base is Permit2ClaimPolicy_Integration_Test {
    using SmartExecutionLib for *;
    using ModuleKitHelpers for *;
    using TestHelperLib for *;

    OneTimeUseIdPolicy internal oncePolicy;

    uint256 internal constant ID = 0x0A11CE;

    function setUp() public virtual override {
        super.setUp();

        oncePolicy = new OneTimeUseIdPolicy(
            ISignatureTransfer(address(env.permit2)), address(env.intentExecutor)
        );

        // The base harness builds the emissary against a MOCK intent executor, so verifyExecution
        // rejects the real one with UnauthorizedSource. Redeploy against the real ADDRESSBOOK so
        // ONE emissary serves both routes.
        smartSessionEmissary = new SmartSessionEmissaryMock(address(ADDRESSBOOK));
        env.smartAccount1
            .installModule({
                moduleTypeId: MODULE_TYPE_VALIDATOR, module: address(smartSessionEmissary), data: ""
            });

        vm.prank(env.smartAccount1.account);
        env.compact.assignEmissary(env.lockTag, address(smartSessionEmissary));

        _injectConsumeIntoPreClaimOps();
    }

    /*//////////////////////////////////////////////////////////////
                                  SETUP
    //////////////////////////////////////////////////////////////*/

    /// @dev Puts the injected `consume` into the order's pre-claim ops and re-derives the hashes
    ///      that cover them. The default sigMode is a 1271 one, which is what the arbiter route
    ///      needs: the pre-claim validation and the unlock share one signature envelope.
    /// @dev Re-points the order at a different real Permit2 nonce, re-injecting the consume so
    ///      its witness still names THIS settlement, and re-deriving the covering hashes.
    function _useNonce(uint256 nonce) internal {
        $intent.nonce = nonce;
        _injectConsumeIntoPreClaimOps();
    }

    function _injectConsumeIntoPreClaimOps() internal {
        Execution[] memory ops = new Execution[](1);
        ops[0] = Execution({
            target: address(oncePolicy),
            value: 0,
            callData: abi.encodeCall(IOneTimeUseIdPolicy.consumeFor, (ID, $intent.nonce))
        });

        $intent.element.mandate.originOps = ops.toOperation();

        $intent.permit2Hash = hashPermit2(
            $intent.sponsor, $intent.nonce, $intent.expires, arbiter, $intent.element
        );
        $intent.digest = _hashTypedDataPermit2(block.chainid, $intent.permit2Hash);
    }

    /// @dev Override to register further actions on the session. Empty by default: the matrix
    ///      registers only what an honest settlement calls.
    function _extraActions(PolicyData[] memory) internal virtual returns (ActionData[] memory) {
        return new ActionData[](0);
    }

    /// @dev The once-policy goes on the 1271 list AND on EVERY action. The 1271 list is an AND, so
    ///      `Permit2ClaimPolicy` still bounds WHAT may settle while this bounds HOW MANY TIMES.
    /// @param bounded false swaps the once-policy for permissive ones, so the lists are non-empty
    ///        but nothing bounds repetition. An EMPTY list is not the control — minPolicies is 1.
    function _enableSession(bool bounded) internal {
        activeFieldMode = FIELD_ARBITER;

        PolicyData[] memory erc1271Policies = new PolicyData[](bounded ? 2 : 1);
        erc1271Policies[0] = PolicyData({
            policy: address(permit2ClaimPolicy),
            initData: abi.encodePacked(
                _createModeConfig(FIELD_ARBITER, MODE_CHECK_STORAGE), uint8(1), arbiter
            )
        });
        if (bounded) {
            erc1271Policies[1] = PolicyData({
                policy: address(oncePolicy), initData: abi.encodePacked(bytes32(ID))
            });
        }

        PolicyData[] memory actionPolicies = new PolicyData[](1);
        actionPolicies[0] = bounded
            ? PolicyData({ policy: address(oncePolicy), initData: abi.encodePacked(bytes32(ID)) })
            : PolicyData({ policy: address(sudoPolicy), initData: "" });

        ActionData[] memory extra = _extraActions(actionPolicies);
        ActionData[] memory actions = new ActionData[](2 + extra.length);
        actions[0] = ActionData({
            actionTarget: address(oncePolicy),
            actionTargetSelector: IOneTimeUseIdPolicy.consume.selector,
            actionPolicies: actionPolicies
        });
        actions[1] = ActionData({
            actionTarget: address(env.target),
            actionTargetSelector: MockTarget.targetFn.selector,
            actionPolicies: actionPolicies
        });
        for (uint256 i; i < extra.length; ++i) {
            actions[2 + i] = extra[i];
        }

        ERC7739Context[] memory allowedContent = new ERC7739Context[](1);
        allowedContent[0].contentNames = new string[](1);
        allowedContent[0].contentNames[0] = "";
        allowedContent[0].appDomainSeparator = bytes32(0);

        Session memory session = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: keccak256(abi.encodePacked("oneTimeUseIdMatrix", block.timestamp)),
            sessionValidatorInitData: "mockInitData",
            erc7739Policies: ERC7739Data({
                allowedERC7739Content: allowedContent, erc1271Policies: erc1271Policies
            }),
            actions: actions,
            claimPolicies: new PolicyData[](0)
        });

        Session[] memory sessions = new Session[](1);
        sessions[0] = session;

        vm.prank(env.smartAccount1.account);
        PermissionId[] memory ids = smartSessionEmissary.enableSessions(sessions, bytes12(0));
        defaultPermissionId = ids[0];
    }

    /*//////////////////////////////////////////////////////////////
                            PERMIT2 ROUTE (REAL)
    //////////////////////////////////////////////////////////////*/

    /// @dev Split from the claim because `_createPolicyData` makes an external staticcall — an
    ///      `expectRevert` armed before it binds to THAT call and passes on the prepare step.
    function _preparePermit2Settlement() internal returns (bytes memory) {
        Types.Order memory order = _getPermit2Order();
        $intent.userEmissarySig = _createSmartSessionSignature(_createPolicyData());

        return abi.encodeCall(
            MockAdapter.mock_permit2_handleClaim,
            (MockAdapter.ClaimDataPermit2({
                    order: order, userSigs: Types.Signatures($intent.userEmissarySig, "")
                }))
        );
    }

    function _settleViaPermit2() internal {
        _claim(block.chainid, abi.encodePacked(env.solver.addr), _preparePermit2Settlement());
    }

    /*//////////////////////////////////////////////////////////////
                           EXECUTOR ROUTE (REAL)
    //////////////////////////////////////////////////////////////*/

    /// @dev The emissary path takes a different envelope from the 1271 path: mode, permissionId
    ///      and packed signature directly, with no module-address prefix.
    function _emissarySig() internal view returns (bytes memory) {
        bytes memory validatorSig =
            abi.encodePacked(bytes32(uint256(0x1234)), bytes32(uint256(0x5678)), uint8(27));

        return abi.encodePacked(
            SmartSessionMode.USE,
            defaultPermissionId,
            uint256(validatorSig.length) + 64,
            validatorSig
        );
    }

    /// @dev Parameterised on the executor nonce because the executor refuses a REPLAY of the same
    ///      nonce on its own. A "second settlement fails" test on a reused nonce would be refused
    ///      by the executor before any policy runs, and would prove nothing.
    function _settleViaExecutor(uint256 executorNonce, uint256 param) internal {
        Execution[] memory calls = new Execution[](2);
        calls[0] = Execution({
            target: address(oncePolicy),
            value: 0,
            callData: abi.encodeCall(IOneTimeUseIdPolicy.consume, (ID))
        });
        calls[1] = Execution({
            target: address(env.target),
            value: 0,
            callData: abi.encodeCall(MockTarget.targetFn, (param))
        });

        IStandaloneIntentExecutor.SingleChainOps memory signedOps;
        signedOps.account = env.smartAccount1.account;
        signedOps.nonce = executorNonce;
        signedOps.ops = SmartExecutionLib.SigMode.EMISSARY_EXECUTION.encode(calls);
        signedOps.signature = _emissarySig();

        vm.prank(env.solver.addr);
        env.intentExecutor.executeSinglechainOps(signedOps);
    }

    function _settleViaExecutor(uint256 executorNonce) internal {
        _settleViaExecutor(executorNonce, 42);
    }

    /// @dev The same settlement with the injected `consume` OMITTED. This is what a settler who
    ///      can choose their own ops would build, and it is the shape the install-time
    ///      requirement exists to forbid.
    function _settleViaExecutorWithoutConsume(uint256 executorNonce, uint256 param) internal {
        Execution[] memory calls = new Execution[](1);
        calls[0] = Execution({
            target: address(env.target),
            value: 0,
            callData: abi.encodeCall(MockTarget.targetFn, (param))
        });

        IStandaloneIntentExecutor.SingleChainOps memory signedOps;
        signedOps.account = env.smartAccount1.account;
        signedOps.nonce = executorNonce;
        signedOps.ops = SmartExecutionLib.SigMode.EMISSARY_EXECUTION.encode(calls);
        signedOps.signature = _emissarySig();

        vm.prank(env.solver.addr);
        env.intentExecutor.executeSinglechainOps(signedOps);
    }

    function _burned() internal view returns (bool) {
        return oncePolicy.isConsumed($intent.sponsor, ID);
    }
}

/// @title Orderings that can be proven inside one transaction
/// @notice Every ordering here ENDS in an executor settlement, and `checkAction` is strict — it
///         has no same-transaction tolerance — so the refusal is observable without splitting the
///         transaction. The orderings that end in a Permit2 settlement cannot be proven this way
///         and live in their own contracts below.
contract OneTimeUseIdMatrixE2E_Test is OneTimeUseIdE2E_Base {
    /*//////////////////////////////////////////////////////////////
                          EITHER ROUTE WORKS ALONE
    //////////////////////////////////////////////////////////////*/

    function test_permit2RouteSettles() public {
        _enableSession(true);
        _settleViaPermit2();

        assertTrue(_burned(), "the Permit2 settlement completed, and its pre-claim ops burned");
    }

    function test_executorRouteSettles() public {
        _enableSession(true);
        _settleViaExecutor(0);

        assertEq(env.target.param(), 42, "the executor settlement executed");
        assertTrue(_burned(), "and burned the id");
    }

    /*//////////////////////////////////////////////////////////////
                             ...BUT ONLY ONCE
    //////////////////////////////////////////////////////////////*/

    /// @dev ORDERING: Permit2 -> executor. The cross-family diagonal that needed an external
    ///      consumable in every earlier design. Here the Permit2 settlement's own pre-claim ops
    ///      burn OUR record, so the executor route reads it directly.
    function test_permit2ThenExecutor_refused() public {
        _enableSession(true);
        _settleViaPermit2();

        vm.expectRevert();
        _settleViaExecutor(0);
    }

    /// @dev ORDERING: executor -> executor on a FRESH executor nonce. The executor does not close
    ///      this — the settler picks the nonce — so only the policy can.
    function test_executorThenExecutorFreshNonce_refused() public {
        _enableSession(true);
        _settleViaExecutor(0);

        vm.expectRevert();
        _settleViaExecutor(1);
    }

    function test_noFurtherExecutorSettlementOnAnyNonce() public {
        _enableSession(true);
        _settleViaExecutor(0);

        for (uint256 i = 1; i <= 5; ++i) {
            vm.expectRevert();
            _settleViaExecutor(i);
        }
    }

    /*//////////////////////////////////////////////////////////////
                                 CONTROLS
    //////////////////////////////////////////////////////////////*/

    /// @dev CONTROL for executor -> executor. Even with the once-policy swapped for a permissive
    ///      one, a same-id second settlement that injects `consume` is refused, because `consume`
    ///      reverts on an already-burned id. The genuine unbounded residual is a settlement that
    ///      OMITS the burn (see test_aSettlementOmittingConsumeIsUnbounded).
    function test_control_executorDoubleConsumeIsRefusedEvenWithoutThePolicy() public {
        _enableSession(false);

        _settleViaExecutor(0, 42);
        assertEq(env.target.param(), 42, "the first executor settlement executed");

        vm.expectRevert();
        _settleViaExecutor(1, 43);
    }

    /// @dev ORDERING: Permit2 -> Permit2, which this policy does NOT own. Permit2 refuses the
    ///      replay of its own nonce before any policy runs, so this is asserted to record which
    ///      mechanism covers the cell — not to claim credit for it.
    function test_permit2ThenPermit2_refusedByPermit2Itself() public {
        _enableSession(true);
        _settleViaPermit2();

        bytes memory adapterCalldata = _preparePermit2Settlement();

        vm.expectRevert();
        _claim(block.chainid, abi.encodePacked(env.solver.addr), adapterCalldata);
    }

    /*//////////////////////////////////////////////////////////////
                    THE INSTALL-TIME REQUIREMENT, DEMONSTRATED
    //////////////////////////////////////////////////////////////*/

    /// @dev THE residual, and the one thing this policy cannot enforce for itself. `checkAction`
    ///      only READS; the burn is the injected `consume`. A settlement that omits it therefore
    ///      burns nothing, and the session stays open however many times it is repeated.
    ///
    ///      The guarantee is "a settlement which DOES burn cannot be followed by another", NOT
    ///      "every settlement burns". Closing the gap is an install-time obligation — the
    /// injected
    ///      call must sit inside the SIGNED intent so removing it invalidates the signature — and
    ///      nothing in the contract can check that. Asserted here rather than described, so the
    ///      cost of getting the install wrong is visible.
    function test_aSettlementOmittingConsumeIsUnbounded() public {
        _enableSession(true);

        _settleViaExecutorWithoutConsume(0, 42);
        assertFalse(_burned(), "nothing burned, because nothing called consume");

        _settleViaExecutorWithoutConsume(1, 43);
        assertEq(env.target.param(), 43, "and so a second settlement lands");
    }

    /// @dev The contrast: the identical pair WITH the injected call is refused on the second.
    ///      Together these two say exactly what the requirement buys.
    function test_theSamePairWithConsumeIsRefused() public {
        _enableSession(true);

        _settleViaExecutor(0, 42);
        assertTrue(_burned(), "the injected call burned");

        vm.expectRevert();
        _settleViaExecutor(1, 43);
    }

    /// @dev CONTROL for Permit2 -> executor
    function test_control_permit2ThenExecutorDoubleConsumeIsRefused() public {
        _enableSession(false);

        // The Permit2 settlement's consumeFor burns the id; the executor settlement's injected
        // consume then reverts on the already-burned id - the burn record is shared across routes
        // independently of the once-policy being installed as an action guard.
        _settleViaPermit2();

        vm.expectRevert();
        _settleViaExecutor(0, 43);
    }
}

/// @title The orderings that END in a Permit2 settlement
/// @notice These CANNOT be proven inside one test body, and the reason is the design itself.
///         The 1271 read tolerates a burn from the transaction currently running — it has to,
///         because the arbiter route reads 1271 again after its own pre-claim ops have burned.
///         A forge test body IS one transaction, so a same-body "settle twice" test would be
///         tolerated and would pass while proving nothing.
///
///         Transient storage IS cleared between `setUp` and the test body. Running the first
///         settlement in `setUp` is therefore the only way to make the second one a genuinely
///         later transaction.
abstract contract OneTimeUseIdCrossTx_Base is OneTimeUseIdE2E_Base {
    /// @dev Overridden by the controls
    function _bounded() internal view virtual returns (bool) {
        return true;
    }

    /// @dev Settlement ONE. Runs in setUp so the test body is a different transaction.
    function _firstSettlement() internal virtual;

    function setUp() public virtual override {
        super.setUp();
        _enableSession(_bounded());
        _firstSettlement();
    }
}

/// @dev ORDERING: executor -> Permit2
contract OneTimeUseId_ExecutorThenPermit2_Test is OneTimeUseIdCrossTx_Base {
    function _firstSettlement() internal override {
        _settleViaExecutor(0);
    }

    function test_theFirstSettlementBurned() public view {
        assertTrue(_burned(), "setUp's executor settlement burned the id");
    }

    function test_permit2IsRefusedInALaterTransaction() public {
        bytes memory adapterCalldata = _preparePermit2Settlement();

        vm.expectRevert();
        _claim(block.chainid, abi.encodePacked(env.solver.addr), adapterCalldata);
    }
}

/// @dev CONTROL for executor -> Permit2
contract OneTimeUseId_ExecutorThenPermit2_Control_Test is OneTimeUseIdCrossTx_Base {
    function _bounded() internal view override returns (bool) {
        return false;
    }

    function _firstSettlement() internal override {
        _settleViaExecutor(0);
    }

    /// @dev The burn still happens — the injected `consume` is in the order either way — so the
    ///      control is that the settlement LANDS despite it, which isolates the refusal above to
    ///      the policy reading that burn rather than to anything about the settlement itself.
    function test_permit2LandsWhenNothingBoundsIt() public {
        assertTrue(_burned(), "setUp's settlement burned, exactly as in the bounded case");

        _settleViaPermit2();
    }
}
