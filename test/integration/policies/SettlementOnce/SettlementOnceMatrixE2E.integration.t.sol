// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {
    Permit2ClaimPolicy_Integration_Test
} from "../Permit2ClaimPolicy/Permit2ClaimPolicy.integration.t.sol";

import { MockAdapter } from "@mocks/MockAdapter.sol";
import { ModuleKitHelpers } from "@modulekit/ModuleKit.sol";
import { SettlementOncePolicy } from "@policies/once/SettlementOncePolicy.sol";
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
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";
import { MODULE_TYPE_VALIDATOR } from "@modulekit/accounts/common/interfaces/IERC7579Module.sol";
import { SmartExecutionLib } from "@compact-utils/common/SmartExecutionLib.sol";
import { Types } from "@compact-utils/types/OrderTypes.sol";
import {
    IStandaloneIntentExecutor
} from "@compact-utils/executor/interfaces/IStandaloneIntent.sol";
import { FIELD_ARBITER, MODE_CHECK_STORAGE } from "@policies/claim/base/types/BaseDataTypes.sol";

/// @title The full matrix, end to end, on the action surface
/// @notice The #55 counterpart to the multiplexer's matrix test. Both routes settle for real:
///
///   Permit2   router -> arbiter -> Permit2.permitWitnessTransferFrom
///                     -> account.isValidSignature
///                     -> Permit2ClaimPolicy AND SettlementOncePolicy   (the 1271 half)
///
///   executor  solver -> StandaloneIntentExecutor.executeSinglechainOps
///                     -> sigMode EMISSARY_EXECUTION -> emissary.verifyExecution
///                     -> _enforceActionPolicies -> SettlementOncePolicy   (the action half)
///
/// The policy is installed on BOTH surfaces with the SAME pinned nonce, which is the production
/// shape and the one the earlier e2e did not exercise — that test installed the action half only,
/// so three of four orderings were untested.
contract SettlementOnceMatrixE2E_Test is Permit2ClaimPolicy_Integration_Test {
    using SmartExecutionLib for *;
    using ModuleKitHelpers for *;

    SettlementOncePolicy internal oncePolicy;

    /// @dev matches `$intent.nonce` from the parent setUp
    uint256 internal constant PINNED = 1337;

    function setUp() public virtual override {
        super.setUp();

        oncePolicy = new SettlementOncePolicy(ISignatureTransfer(address(env.permit2)));

        // The base harness deploys the emissary against a MOCK intent executor, so
        // `verifyExecution` rejects the real one with UnauthorizedSource. Redeploy it against the
        // real ADDRESSBOOK and install it, so ONE emissary serves both routes: the 1271 path for
        // Permit2 settlements and verifyExecution for executor settlements.
        smartSessionEmissary = new SmartSessionEmissaryMock(address(ADDRESSBOOK));
        env.smartAccount1
            .installModule({
                moduleTypeId: MODULE_TYPE_VALIDATOR, module: address(smartSessionEmissary), data: ""
            });

        vm.prank(env.smartAccount1.account);
        env.compact.assignEmissary(env.lockTag, address(smartSessionEmissary));
    }

    /*//////////////////////////////////////////////////////////////
                                  SETUP
    //////////////////////////////////////////////////////////////*/

    /// @dev Installs the policy on BOTH surfaces with one pinned nonce. The 1271 list is an AND,
    ///      so `Permit2ClaimPolicy` still binds the blob to the digest while this bounds how many
    ///      times it may settle — both read the nonce at the same offset, so one blob serves
    /// both.
    /// @param boundExecutor true installs the once-policy on the action surface; false installs a
    ///        permissive policy instead, so the list is non-empty but nothing bounds repetition.
    ///        An EMPTY list is not the control — `minPolicies: 1` makes that revert outright.
    /// @param bound1271 true installs the once-policy alongside Permit2ClaimPolicy on the 1271
    ///        surface; false installs only Permit2ClaimPolicy, so the Permit2 route is unbounded.
    ///        Needed as the control for the executor -> Permit2 diagonal.
    function _enableOnceSession(bool boundExecutor, bool bound1271) internal {
        activeFieldMode = FIELD_ARBITER;

        PolicyData[] memory erc1271Policies = new PolicyData[](bound1271 ? 2 : 1);
        erc1271Policies[0] = PolicyData({
            policy: address(permit2ClaimPolicy),
            initData: abi.encodePacked(
                _createModeConfig(FIELD_ARBITER, MODE_CHECK_STORAGE), uint8(1), arbiter
            )
        });
        if (bound1271) {
            erc1271Policies[1] = PolicyData({
                policy: address(oncePolicy), initData: abi.encodePacked(bytes32(PINNED))
            });
        }

        PolicyData[] memory actionPolicies = new PolicyData[](1);
        actionPolicies[0] = boundExecutor
            ? PolicyData({
                policy: address(oncePolicy), initData: abi.encodePacked(bytes32(PINNED))
            })
            : PolicyData({ policy: address(sudoPolicy), initData: "" });

        ActionData[] memory actions = new ActionData[](1);
        actions[0] = ActionData({
            actionTarget: address(env.target),
            actionTargetSelector: MockTarget.targetFn.selector,
            actionPolicies: actionPolicies
        });

        _enable(erc1271Policies, actions, "onceMatrix");
    }

    /// @dev Enables a session and records its permissionId. Extracted so the tests that need a
    ///      non-standard policy list can build one without duplicating the session shape.
    function _enable(
        PolicyData[] memory erc1271Policies,
        ActionData[] memory actions,
        string memory salt
    )
        internal
    {
        ERC7739Context[] memory allowedContent = new ERC7739Context[](1);
        allowedContent[0].contentNames = new string[](1);
        allowedContent[0].contentNames[0] = "";
        allowedContent[0].appDomainSeparator = bytes32(0);

        Session memory session = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: keccak256(abi.encodePacked(salt, block.timestamp)),
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

    /// @dev The UNSAFE configuration the policy's install-time requirement warns about: the
    ///      once-policy is the ONLY 1271 policy, so nothing binds the blob it reads to the digest
    ///      Permit2 actually settles. `minPoliciesToEnforce` is 1, so this is a legal config and
    ///      nothing rejects it.
    function _enableOnceSessionAloneOn1271() internal {
        activeFieldMode = FIELD_ARBITER;

        PolicyData[] memory erc1271Policies = new PolicyData[](1);
        erc1271Policies[0] = PolicyData({
            policy: address(oncePolicy), initData: abi.encodePacked(bytes32(PINNED))
        });

        PolicyData[] memory actionPolicies = new PolicyData[](1);
        actionPolicies[0] = PolicyData({
            policy: address(oncePolicy), initData: abi.encodePacked(bytes32(PINNED))
        });

        ActionData[] memory actions = new ActionData[](1);
        actions[0] = ActionData({
            actionTarget: address(env.target),
            actionTargetSelector: MockTarget.targetFn.selector,
            actionPolicies: actionPolicies
        });

        _enable(erc1271Policies, actions, "onceAlone");
    }

    /*//////////////////////////////////////////////////////////////
                            PERMIT2 ROUTE (REAL)
    //////////////////////////////////////////////////////////////*/

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

    /// @dev Settles for real on `realNonce` while the blob handed to the 1271 policies claims
    ///      `blobNonce`. Both are built from `$intent.nonce`, so they are built one at a time —
    ///      which is precisely the divergence a policy that only reads the blob cannot see.
    /// @dev Builds a settlement that lands for real on `realNonce` while the blob handed to the
    ///      1271 policies claims `blobNonce`. Both are built from `$intent.nonce`, so they are
    ///      built one at a time — precisely the divergence a policy that only reads the blob
    ///      cannot see.
    ///
    ///      Kept separate from the claim because `_createPolicyData` makes an external staticcall:
    ///      an `expectRevert` armed before this would bind to THAT call and pass on the prepare
    ///      step, never reaching the settlement it is supposed to be asserting about.
    function _preparePermit2Claiming(
        uint256 realNonce,
        uint256 blobNonce
    )
        internal
        returns (bytes memory)
    {
        $intent.nonce = blobNonce;
        $intent.userEmissarySig = _createSmartSessionSignature(_createPolicyData());

        $intent.nonce = realNonce;
        Types.Order memory order = _getPermit2Order();

        return abi.encodeCall(
            MockAdapter.mock_permit2_handleClaim,
            (MockAdapter.ClaimDataPermit2({
                    order: order, userSigs: Types.Signatures($intent.userEmissarySig, "")
                }))
        );
    }

    function _settleViaPermit2Claiming(uint256 realNonce, uint256 blobNonce) internal {
        _claim(
            block.chainid,
            abi.encodePacked(env.solver.addr),
            _preparePermit2Claiming(realNonce, blobNonce)
        );
    }

    /*//////////////////////////////////////////////////////////////
                           EXECUTOR ROUTE (REAL)
    //////////////////////////////////////////////////////////////*/

    function _executorOps() internal view returns (Execution[] memory calls) {
        return _executorOps(42);
    }

    /// @dev Parameterised so a control's SECOND settlement writes a different value — otherwise
    ///      the terminal assertion is satisfied by the first settlement alone and carries no
    ///      information about whether the second one ran.
    function _executorOps(uint256 param) internal view returns (Execution[] memory calls) {
        calls = new Execution[](1);
        calls[0] = Execution({
            target: address(env.target),
            value: 0,
            callData: abi.encodeCall(MockTarget.targetFn, (param))
        });
    }

    /// @dev The emissary path takes a DIFFERENT envelope from the 1271 path:
    /// `_enforceActionPolicies` unpacks (mode, permissionId, packedSig) directly, with no
    /// module-address prefix. Using
    ///      the parent's 1271 builder here yields InvalidSignature.
    function _emissarySig() internal view returns (bytes memory) {
        bytes memory validatorSig =
            abi.encodePacked(bytes32(uint256(0x1234)), bytes32(uint256(0x5678)), uint8(27));

        return abi.encodePacked(
            SmartSessionMode.USE,
            defaultPermissionId,
            uint256(validatorSig.length) + 64, // policyDataOffset
            validatorSig
        );
    }

    /// @dev A REAL executor settlement, validated through the emissary's action-policy path
    function _settleViaExecutor(uint256 executorNonce) internal {
        _settleViaExecutor(executorNonce, 42);
    }

    function _settleViaExecutor(uint256 executorNonce, uint256 param) internal {
        IStandaloneIntentExecutor.SingleChainOps memory signedOps;
        signedOps.account = env.smartAccount1.account;
        signedOps.nonce = executorNonce;
        signedOps.ops = SmartExecutionLib.SigMode.EMISSARY_EXECUTION.encode(_executorOps(param));
        signedOps.signature = _emissarySig();

        vm.prank(env.solver.addr);
        env.intentExecutor.executeSinglechainOps(signedOps);
    }

    function _permit2Burned(uint256 nonce) internal view returns (bool) {
        return (env.permit2.nonceBitmap($intent.sponsor, nonce >> 8) >> (nonce & 0xff)) & 1 == 1;
    }

    /*//////////////////////////////////////////////////////////////
                          EITHER ROUTE WORKS ALONE
    //////////////////////////////////////////////////////////////*/

    function test_permit2RouteSettles() public {
        _enableOnceSession(true, true);

        _settleViaPermit2();

        assertTrue(_permit2Burned(PINNED), "the real Permit2 nonce is burned");
    }

    function test_executorRouteSettles() public {
        _enableOnceSession(true, true);

        _settleViaExecutor(0);

        assertEq(env.target.param(), 42, "the executor settlement executed");
        assertTrue(
            oncePolicy.isExecutorSpent(address(smartSessionEmissary), $intent.sponsor, PINNED),
            "and the policy recorded the spend"
        );
    }

    /*//////////////////////////////////////////////////////////////
                           ...BUT ONLY ONE OF THEM
    //////////////////////////////////////////////////////////////*/

    /// @dev ORDERING: executor -> Permit2. The action half burned the shared record; the 1271
    ///      half reads it and refuses. Attributable via the control below, which shows the same
    ///      sequence settling once the once-policy is off the 1271 surface.
    function test_executorThenPermit2_refused() public {
        _enableOnceSession(true, true);

        _settleViaExecutor(0);

        bytes memory adapterCalldata = _preparePermit2Settlement();

        vm.expectRevert();
        _claim(block.chainid, abi.encodePacked(env.solver.addr), adapterCalldata);
    }

    /// @dev ORDERING: Permit2 -> executor. The real Permit2 burn must close the executor route.
    function test_permit2ThenExecutor_refused() public {
        _enableOnceSession(true, true);

        _settleViaPermit2();

        vm.expectRevert();
        _settleViaExecutor(0);
    }

    /// @dev ORDERING: executor -> executor on a FRESH executor nonce. The executor itself does not
    ///      close this; only the policy's own record can. The eleven-settlements shape.
    function test_executorThenExecutorFreshNonce_refused() public {
        _enableOnceSession(true, true);

        _settleViaExecutor(0);

        vm.expectRevert();
        _settleViaExecutor(1);
    }

    /*//////////////////////////////////////////////////////////////
                                 CONTROL
    //////////////////////////////////////////////////////////////*/

    /// @dev THE CONTROL. Swap the once-policy for a permissive one and the identical second
    ///      settlement on a fresh nonce goes straight through — so every refusal above is this
    ///      policy's doing, not the executor's nonce and not the harness.
    function test_withAPermissivePolicyTheExecutorRouteIsUnbounded() public {
        _enableOnceSession(false, true);

        _settleViaExecutor(0, 42);
        _settleViaExecutor(1, 43);

        assertEq(env.target.param(), 43, "the SECOND executor settlement executed");
    }

    /// @dev CONTROL for Permit2 -> executor. With a permissive action policy the same sequence
    ///      succeeds, so the refusal above is this policy reading Permit2's burn — not the
    ///      executor's own nonce, and not some unrelated validation failure. This matters more
    ///      than usual here: `_verifyExecutionWithEmissary` wraps verifyExecution in a bare
    ///      try/catch, so EVERY executor-route failure collapses to one generic InvalidSignature
    ///      and `expectRevert` cannot distinguish causes. A differential control is the only
    ///      attribution mechanism available on this route.
    function test_control_permit2ThenExecutorIsOpenWithoutTheOncePolicy() public {
        _enableOnceSession(false, true);

        _settleViaPermit2();
        _settleViaExecutor(0, 43);

        assertEq(env.target.param(), 43, "the executor route is open when nothing bounds it");
    }

    /// @dev Diagnostic: does the Permit2 route work AT ALL in the control's configuration, with
    ///      nothing settled first? If this fails, the control below is failing on the config
    ///      rather than on the ordering, and the ordering test it backs proves nothing.
    function test_diag_permit2SettlesWithoutTheOncePolicyOn1271() public {
        _enableOnceSession(true, false);

        _settleViaPermit2();

        assertTrue(_permit2Burned(PINNED), "Permit2 settles with only the claim policy on 1271");
    }

    /// @dev Diagnostic: with the once-policy on NEITHER surface, does an executor settlement
    ///      still break a following Permit2 settlement? If yes, the interference is the harness
    ///      or the protocol, and has nothing to do with this policy.
    function test_diag_executorSettlementBreaksPermit2WithNoOncePolicyAtAll() public {
        _enableOnceSession(false, false);

        _settleViaExecutor(0);
        _settleViaPermit2();

        assertTrue(_permit2Burned(PINNED), "Permit2 settles after an executor settlement");
    }

    /// @dev CONTROL for executor -> Permit2: with the once-policy off the 1271 surface the same
    ///      sequence settles, so the refusal above is this policy's doing.
    ///
    ///      This control spent a while failing, and the cause was the control itself — the
    ///      `bound1271` parameter was silently dead (the array was hardcoded to length 2), so
    ///      "without the once-policy" still installed it. Worth remembering that a failing
    ///      control is not automatically evidence about the subject.
    function test_control_executorThenPermit2IsOpenWithoutTheOncePolicy() public {
        _enableOnceSession(true, false);

        _settleViaExecutor(0);
        _settleViaPermit2();

        assertTrue(_permit2Burned(PINNED), "the Permit2 route is open when nothing bounds it");
    }

    /// @dev Permit2 -> Permit2 is closed by Permit2 itself, before any policy runs. Asserted so
    ///      the one place InvalidNonce IS the intended mechanism says so.
    function test_permit2ThenPermit2_refusedByPermit2Itself() public {
        _enableOnceSession(true, true);

        _settleViaPermit2();

        bytes memory adapterCalldata = _preparePermit2Settlement();

        vm.expectRevert();
        _claim(block.chainid, abi.encodePacked(env.solver.addr), adapterCalldata);
    }

    /// @dev And the adjacent property worth pinning: an EMPTY action-policy list does not make the
    ///      executor route unbounded, it makes it unusable. `_enforceActionPolicies` runs with
    ///      minPolicies = 1, so nothing installed means NoPoliciesSet. That is why leaving the
    ///      action list empty is itself a control, and why installing any action policy at all is
    ///      what opens this route.
    function test_anEmptyActionListClosesTheExecutorRouteEntirely() public {
        activeFieldMode = FIELD_ARBITER;

        PolicyData[] memory erc1271Policies = new PolicyData[](1);
        erc1271Policies[0] = PolicyData({
            policy: address(oncePolicy), initData: abi.encodePacked(bytes32(PINNED))
        });

        ERC7739Context[] memory allowedContent = new ERC7739Context[](1);
        allowedContent[0].contentNames = new string[](1);
        allowedContent[0].contentNames[0] = "";
        allowedContent[0].appDomainSeparator = bytes32(0);

        Session memory session = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: keccak256(abi.encodePacked("onceMatrixEmpty", block.timestamp)),
            sessionValidatorInitData: "mockInitData",
            erc7739Policies: ERC7739Data({
                allowedERC7739Content: allowedContent, erc1271Policies: erc1271Policies
            }),
            actions: new ActionData[](0),
            claimPolicies: new PolicyData[](0)
        });

        Session[] memory sessions = new Session[](1);
        sessions[0] = session;

        vm.prank(env.smartAccount1.account);
        PermissionId[] memory ids = smartSessionEmissary.enableSessions(sessions, bytes12(0));
        defaultPermissionId = ids[0];

        vm.expectRevert();
        _settleViaExecutor(0);
    }

    /*//////////////////////////////////////////////////////////////
                    THE CO-INSTALLATION REQUIREMENT, PROVEN
    //////////////////////////////////////////////////////////////*/

    /// @dev The policy documents that its 1271 half MUST share a list with a policy that binds the
    ///      blob to the digest, and that nothing enforces it. Nothing did — so here is what the
    ///      unsafe config actually costs.
    ///
    ///      The 1271 half reads the nonce out of a caller-supplied blob. Installed alone, a
    ///      settler presents the pinned nonce on every claim while Permit2 settles a different one
    ///      each time. The half is `view`, so it burns nothing and has nothing to compare against.
    function test_aloneOn1271_thePinIsFictionAndTheRouteIsUnbounded() public {
        _enableOnceSessionAloneOn1271();

        _settleViaPermit2Claiming({ realNonce: 9001, blobNonce: PINNED });
        _settleViaPermit2Claiming({ realNonce: 9002, blobNonce: PINNED });

        assertTrue(_permit2Burned(9001), "first settlement landed on a nonce nobody pinned");
        assertTrue(_permit2Burned(9002), "and so did the second");
        assertFalse(_permit2Burned(PINNED), "while the pinned nonce was never spent at all");
    }

    /// @dev And it is worse than an unbounded Permit2 route: because the pinned nonce is never
    ///      actually burned, `checkAction`'s `_permit2Spent` read stays false, so the executor
    ///      route is still open on top. Two families, one session, three settlements.
    function test_aloneOn1271_theExecutorRouteStaysOpenOnTop() public {
        _enableOnceSessionAloneOn1271();

        _settleViaPermit2Claiming({ realNonce: 9001, blobNonce: PINNED });
        _settleViaExecutor({ executorNonce: 0, param: 43 });

        assertEq(env.target.param(), 43, "the executor settled after a Permit2 settlement");
    }

    /// @dev The other half of the requirement: with `Permit2ClaimPolicy` co-installed the exact
    ///      same lie is refused, because the claim policy recomputes the digest from the blob and
    ///      compares it to `hash`. The 1271 list is an AND, so one honest reader is enough.
    ///
    ///      This pair is the requirement — alone it is fiction, together it holds — and it is
    /// the
    ///      reason the doc block calls the partner load-bearing rather than advisory.
    function test_withTheClaimPolicyCoInstalledTheSameLieIsRefused() public {
        _enableOnceSession(true, true);

        bytes memory adapterCalldata =
            _preparePermit2Claiming({ realNonce: 9001, blobNonce: PINNED });

        vm.expectRevert();
        _claim(block.chainid, abi.encodePacked(env.solver.addr), adapterCalldata);
    }

    /// @dev CONTROL for the test above: the identical call with a blob that tells the truth
    ///      settles, so the refusal is the nonce lie and not the unusual nonce.
    function test_control_anHonestBlobOnTheSameNonceSettles() public {
        _enableOnceSession(true, true);

        _settleViaPermit2Claiming({ realNonce: PINNED, blobNonce: PINNED });

        assertTrue(_permit2Burned(PINNED), "an honest blob on the pinned nonce settles");
    }

    /*//////////////////////////////////////////////////////////////
                          THE PIN ITSELF, END TO END
    //////////////////////////////////////////////////////////////*/

    /// @dev Every other refusal on this surface goes through `$spent`. This one goes through the
    ///      PIN: the blob is HONEST, so `Permit2ClaimPolicy` is satisfied and the digest matches
    ///      — the only thing left that can refuse it is the once-policy comparing the presented
    ///      nonce to the one it was installed with. Delete that comparison and nothing else in
    ///      this file notices.
    function test_anHonestSettlementOnAnUnpinnedNonceIsRefused() public {
        _enableOnceSession(true, true);

        bytes memory adapterCalldata = _preparePermit2Claiming({ realNonce: 9001, blobNonce: 9001 });

        vm.expectRevert();
        _claim(block.chainid, abi.encodePacked(env.solver.addr), adapterCalldata);
    }

    /// @dev CONTROL. The identical settlement — same real nonce, same honest blob — lands once
    /// the
    ///      once-policy is off the 1271 surface. This isolates the PIN from the nonce value, which
    ///      the co-installation contrast above cannot do on its own: that pair varies both the lie
    ///      and the nonce, so it attributes the lie but says nothing about 9001 itself.
    function test_control_anUnpinnedNonceSettlesWithoutTheOncePolicy() public {
        _enableOnceSession(true, false);

        _settleViaPermit2Claiming({ realNonce: 9001, blobNonce: 9001 });

        assertTrue(_permit2Burned(9001), "an unpinned nonce is open when nothing pins it");
    }
}
