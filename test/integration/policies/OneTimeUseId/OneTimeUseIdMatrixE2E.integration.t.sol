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
import {
    IStandaloneIntentExecutor
} from "@compact-utils/executor/interfaces/IStandaloneIntent.sol";
import { FIELD_ARBITER, MODE_CHECK_STORAGE } from "@policies/claim/base/types/BaseDataTypes.sol";

/// @title OneTimeUseIdPolicy — the full matrix, end to end
/// @notice Both routes settle for real, and BOTH reach the policy through the same surface:
///
///   Permit2   router -> arbiter -> _permit2PreClaimOps
///                     -> executePreClaimOpsWithPermit2Stub
///                     -> sigMode EMISSARY_EXECUTION -> emissary.verifyExecution
///                     -> _enforceActionPolicies -> checkAction        (read)
///                     -> executeOps(preClaimOps)  -> consume          (burn)
///                     then _unlockPermit2 -> real Permit2 -> isValidSignature
///
///   executor  solver -> StandaloneIntentExecutor.executeSinglechainOps
///                     -> sigMode EMISSARY_EXECUTION -> emissary.verifyExecution
///                     -> _enforceActionPolicies -> checkAction        (read)
///                     -> executeOps               -> consume          (burn)
///
/// One read site and one burn site serve both families, which is the whole point: nothing here
/// names a settlement layer, parses a settlement payload, or pins a settlement nonce.
contract OneTimeUseIdMatrixE2E_Test is Permit2ClaimPolicy_Integration_Test {
    using SmartExecutionLib for *;
    using ModuleKitHelpers for *;
    using TestHelperLib for *;

    OneTimeUseIdPolicy internal oncePolicy;

    uint256 internal constant ID = 0x0A11CE;

    function setUp() public virtual override {
        super.setUp();

        oncePolicy = new OneTimeUseIdPolicy();

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

        _setPreClaimOpsToConsume(SmartExecutionLib.SigMode.EMISSARY_EXECUTION);
    }

    /*//////////////////////////////////////////////////////////////
                                  SETUP
    //////////////////////////////////////////////////////////////*/

    /// @dev Puts the injected `consume` into the order's pre-claim ops and re-derives the hashes
    ///      it feeds. The sigMode is a parameter because only three of the seven reach the action
    ///      surface at all — see the sigMode tests at the bottom.
    function _setPreClaimOpsToConsume(SmartExecutionLib.SigMode sigMode) internal {
        Execution[] memory ops = new Execution[](1);
        ops[0] = Execution({
            target: address(oncePolicy),
            value: 0,
            callData: abi.encodeCall(IOneTimeUseIdPolicy.consume, (ID))
        });

        $intent.element.mandate.originOps = ops.toOperation(sigMode);

        $intent.permit2Hash = hashPermit2(
            $intent.sponsor, $intent.nonce, $intent.expires, arbiter, $intent.element
        );
        $intent.digest = _hashTypedDataPermit2(block.chainid, $intent.permit2Hash);
    }

    /// @dev The once-policy goes on EVERY action the session permits — that is the install-time
    ///      requirement, and it is what stops a settler composing a batch out of some other
    ///      permitted action to dodge the read. It is NOT on the 1271 list: the arbiter route
    ///      validates 1271 twice with the burn in between, so a policy there would refuse its own
    ///      settlement.
    /// @param bounded false swaps the once-policy for a permissive one, so the list is non-empty
    ///        but nothing bounds repetition. An EMPTY list is not the control — minPolicies is 1.
    function _enableSession(bool bounded) internal {
        activeFieldMode = FIELD_ARBITER;

        PolicyData[] memory erc1271Policies = new PolicyData[](1);
        erc1271Policies[0] = PolicyData({
            policy: address(permit2ClaimPolicy),
            initData: abi.encodePacked(
                _createModeConfig(FIELD_ARBITER, MODE_CHECK_STORAGE), uint8(1), arbiter
            )
        });

        PolicyData[] memory actionPolicies = new PolicyData[](1);
        actionPolicies[0] = bounded
            ? PolicyData({ policy: address(oncePolicy), initData: abi.encodePacked(bytes32(ID)) })
            : PolicyData({ policy: address(sudoPolicy), initData: "" });

        ActionData[] memory actions = new ActionData[](2);
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

    /// @dev The emissary path takes a different envelope from the 1271 path: the mode,
    ///      permissionId and packed signature directly, with no module-address prefix.
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

    /// @dev A REAL executor settlement carrying the same injected `consume`
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

    function _burned() internal view returns (bool) {
        return oncePolicy.isConsumed($intent.sponsor, ID);
    }

    /*//////////////////////////////////////////////////////////////
             THE FOUNDATION: THE ARBITER ROUTE REACHES checkAction
    //////////////////////////////////////////////////////////////*/

    /// @dev THE claim the whole design rests on. If the Permit2 arbiter route never reached the
    ///      action surface, this policy could not bound it at all — there is no 1271 half to fall
    ///      back on, by design. Asserted by call, not inferred from behaviour.
    function test_theArbiterRouteReachesTheActionSurface() public {
        _enableSession(true);

        vm.expectCall(
            address(oncePolicy), abi.encodeWithSelector(OneTimeUseIdPolicy.checkAction.selector)
        );
        _settleViaPermit2();
    }

    /// @dev ...and the injected execution really does burn, on that same real settlement
    function test_theArbiterRouteBurnsTheId() public {
        _enableSession(true);

        assertFalse(_burned(), "clean before");
        _settleViaPermit2();

        assertTrue(_burned(), "the pre-claim ops consumed the id");
    }

    /*//////////////////////////////////////////////////////////////
                          EITHER ROUTE WORKS ALONE
    //////////////////////////////////////////////////////////////*/

    function test_permit2RouteSettles() public {
        _enableSession(true);
        _settleViaPermit2();

        assertTrue(_burned(), "the Permit2 settlement completed and burned");
    }

    function test_executorRouteSettles() public {
        _enableSession(true);
        _settleViaExecutor(0);

        assertEq(env.target.param(), 42, "the executor settlement executed");
        assertTrue(_burned(), "and burned the id");
    }

    /*//////////////////////////////////////////////////////////////
                           ...BUT ONLY ONE OF THEM
    //////////////////////////////////////////////////////////////*/

    /// @dev ORDERING: executor -> Permit2, the cross-family diagonal
    function test_executorThenPermit2_refused() public {
        _enableSession(true);
        _settleViaExecutor(0);

        bytes memory adapterCalldata = _preparePermit2Settlement();

        vm.expectRevert();
        _claim(block.chainid, abi.encodePacked(env.solver.addr), adapterCalldata);
    }

    /// @dev ORDERING: Permit2 -> executor, the other diagonal
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

    /// @dev ORDERING: Permit2 -> Permit2. Closed by Permit2 itself before any policy runs, so it
    ///      is asserted here only to say which mechanism owns it.
    function test_permit2ThenPermit2_refused() public {
        _enableSession(true);
        _settleViaPermit2();

        bytes memory adapterCalldata = _preparePermit2Settlement();

        vm.expectRevert();
        _claim(block.chainid, abi.encodePacked(env.solver.addr), adapterCalldata);
    }

    /*//////////////////////////////////////////////////////////////
                                 CONTROLS
    //////////////////////////////////////////////////////////////*/

    /// @dev CONTROL for executor -> executor. Swap in a permissive action policy and the same
    ///      second settlement on a fresh nonce goes through, so the refusal above is this policy.
    function test_control_executorRouteIsUnboundedWithoutThePolicy() public {
        _enableSession(false);

        _settleViaExecutor(0, 42);
        _settleViaExecutor(1, 43);

        assertEq(env.target.param(), 43, "the SECOND executor settlement executed");
    }

    /// @dev CONTROL for executor -> Permit2
    function test_control_executorThenPermit2IsOpenWithoutThePolicy() public {
        _enableSession(false);

        _settleViaExecutor(0);
        _settleViaPermit2();

        assertTrue(true, "the Permit2 route is open when nothing bounds it");
    }

    /// @dev CONTROL for Permit2 -> executor
    function test_control_permit2ThenExecutorIsOpenWithoutThePolicy() public {
        _enableSession(false);

        _settleViaPermit2();
        _settleViaExecutor(0, 43);

        assertEq(env.target.param(), 43, "the executor route is open when nothing bounds it");
    }

    /*//////////////////////////////////////////////////////////////
                      THE sigMode CAVEAT, MADE EXPLICIT
    //////////////////////////////////////////////////////////////*/

    /// @dev Only three of the seven sigModes route to verifyExecution, and the pre-claim ops carry
    ///      that byte. Under a 1271-only mode the action surface is never reached on the arbiter
    ///      route, nothing burns, and the session is not bounded there at all. This is the
    ///      operational requirement the design carries; it is asserted rather than described.
    function test_underA1271OnlySigModeTheArbiterRouteNeverReachesThePolicy() public {
        _setPreClaimOpsToConsume(SmartExecutionLib.SigMode.ERC1271_EMISSARY);
        _enableSession(true);

        _settleViaPermit2();

        assertFalse(_burned(), "a 1271-only pre-claim mode never reaches the action surface");
    }

    /// @dev ...and the consequence: a second settlement is then NOT refused
    function test_underA1271OnlySigModeTheArbiterRouteIsUnbounded() public {
        _setPreClaimOpsToConsume(SmartExecutionLib.SigMode.ERC1271_EMISSARY);
        _enableSession(true);

        _settleViaExecutor(0);

        assertTrue(_burned(), "the executor route still burns");

        // and yet the Permit2 route, which never consults the action surface under this mode,
        // is unaffected by that burn
        _settleViaPermit2();
    }
}
