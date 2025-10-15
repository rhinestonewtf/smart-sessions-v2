// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Contracts
import { SameChainAdapter } from "@compact-utils/arbiters/samechain/SameChainAdapter.sol";
import { AlwaysOKAllocator } from "@the-compact/test/AlwaysOKAllocator.sol";
import { EIP712TypeHashLib } from "@compact-utils/types/EIP712TypeHashLib.sol";

// Libraries
import { IdLib } from "@the-compact/lib/IdLib.sol";
import { ModuleKitHelpers } from "@modulekit/ModuleKit.sol";
import { TestHelperLib } from "@compact-utils/tests/Environment.sol";
import { HashLib } from "@smartsessions/lib/HashLib.sol";

// Interfaces
import { ISessionValidator } from "@smartsessions/interfaces/ISessionValidator.sol";

// Types
import { Element, Mandate, Target } from "@compact-utils/types/TheCompactStructs.sol";
import { Execution } from "@smartsessions/lib/ExecutionLib.sol";
import { Types } from "@compact-utils/types/OrderTypes.sol";
import { PolicyData, ActionData, PermissionId } from "@smartsessions/DataTypes.sol";
import { Session } from "@types/DataTypes.sol";
import { EmissaryMode, EMISSARY_SMART_SESSION } from "@lib/ModeLib.sol";

// Test
import { SameChainBaseTest } from "@compact-utils-test/unit/SameChainArbiter/SameChain.t.sol";
import {
    SmartSessionEmissary_Unit_Test
} from "@test/unit/SmartSessionEmissary/SmartSessionEmissary.t.sol";

/// @dev Tests smart session emissary integration with SameChainAdapter
contract SmartSessionEmissary_Integration_Test is
    SameChainBaseTest,
    SmartSessionEmissary_Unit_Test
{
    /* //////////////////////////////////////////////////////////////
                                 LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using ModuleKitHelpers for *;
    using TestHelperLib for *;
    using Types for Execution[];
    using HashLib for *;

    /* //////////////////////////////////////////////////////////////
                                VARIABLES
    //////////////////////////////////////////////////////////////*/

    PermissionId defaultPermissionId;

    /* //////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override(SameChainBaseTest, SmartSessionEmissary_Unit_Test) {
        // Setup SameChainBaseTest
        _deployCompact();
        _deploySmartAccount({ create: true });
        _lockAssets(env.smartAccount1, env.token1, 100 ether);

        adapter = env.sameChainAdapter;
        arbiter = address(adapter.ARBITER());

        _setFillRoute(SameChainAdapter.samechain_compact_handleFill.selector, address(adapter));

        // test
        _sampleExecERC20(env.token2, 10);

        address recipient = env.smartAccount1.account;

        $intent.compact.sponsor = env.smartAccount1.account;
        $intent.compact.nonce = 1337;
        $intent.compact.expires = 4141;

        uint256 notarizedChain = chains.originChain1;

        // Element for originChain 1 (Notarized chain)
        $intent.compact.elements
            .push(
                Element({
                    arbiter: arbiter,
                    chainId: notarizedChain,
                    idsAndAmounts: [toId(env.token1), 100].into(),
                    mandate: Mandate({
                        target: Target({
                            recipient: recipient,
                            tokenOut: [toId(env.token2), 20].into(),
                            targetChain: notarizedChain,
                            fillExpiry: uint32(block.timestamp + 1 hours)
                        }),
                        originOps: intent.targetExecutions,
                        destOps: intent.targetExecutions,
                        q: ""
                    })
                })
            );

        ($intent.claimHash, $intent.elementHashes) = hashCompact(arbiter, $intent.compact);
        $intent.digest = _hashTypedData(notarizedChain, $intent.claimHash);

        env.alwaysOKAllocator = new AlwaysOKAllocator();
        vm.prank(address(env.alwaysOKAllocator));
        uint96 newId = env.compact.__registerAllocator(address(env.alwaysOKAllocator), "");

        // Call the base setup functions for SmartSessionEmissary
        SmartSessionEmissary_Unit_Test.setUp();

        // Setup SmartSessionEmissary with default sudo policy session
        _setupDefaultSession();

        // Setup SmartSessionEmissary as the emissary for the account
        vm.prank(env.smartAccount1.account);
        env.compact.assignEmissary(env.lockTag, address(smartSessionEmissary));

        // Update the user emissary signature with SmartSession mode
        $intent.userEmissarySig = _createSmartSessionSignature($intent.digest);
    }

    /* //////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    // test_fillSameChain from parent will run automatically with our setup
    function test_fillSameChain_sudoPolicy_RevertsWhen_withFailingValidator() public {
        // Setup failing validator session (replaces the default one)
        _setupFailingValidatorSession();

        // Update the signature with the failing validator permission
        $intent.userEmissarySig = _createSmartSessionSignature($intent.digest);

        Types.Order memory order = _getOrder($intent.compact, 0);
        vm.chainId(order.notarizedChainId);

        (bytes32 digest, bytes memory allocatorSig) =
            _allocatorSig(env.orchestrator, order.notarizedChainId, $intent.claimHash);

        (, bytes32[] memory otherElements) = $intent.elementHashes.withoutIndex(0);

        // Expect the fill to fail due to invalid validator
        vm.expectRevert();
        _fill({
            chainId: order.notarizedChainId,
            solverContext: abi.encodePacked(env.solver.addr),
            adapterCalldata: abi.encodeCall(
                SameChainAdapter.samechain_compact_handleFill,
                (SameChainAdapter.FillDataCompact({
                        order: order,
                        userSigs: Types.Signatures($intent.userEmissarySig, ""),
                        otherElements: otherElements,
                        allocatorData: allocatorSig,
                        preClaimGasStipend: type(uint256).max
                    }))
            )
        });
    }

    /* //////////////////////////////////////////////////////////////
                               HELPERS
    //////////////////////////////////////////////////////////////*/

    function _setupDefaultSession() internal {
        // Prank to account
        vm.prank(env.smartAccount1.account);

        // Setup policies with sudo policy (always allows)
        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });

        // Setup session with YesSessionValidator (always validates)
        Session memory session = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: keccak256("defaultSalt"),
            sessionValidatorInitData: "mockInitData",
            erc1271Policies: policyDatas,
            actions: new ActionData[](0)
        });

        // Enable session
        Session[] memory sessions = new Session[](1);
        sessions[0] = session;

        PermissionId[] memory permissionIds =
            smartSessionEmissary.enableSessions(sessions, env.lockTag, address(env.compact));

        defaultPermissionId = permissionIds[0];
    }

    function _setupFailingValidatorSession() internal {
        // Clear existing permission (start fresh)
        defaultPermissionId = PermissionId.wrap(bytes32(0));

        // Prank to account
        vm.prank(env.smartAccount1.account);

        // Setup policies with sudo policy
        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });

        // Setup session with NoSessionValidator (always fails)
        Session memory session = Session({
            sessionValidator: ISessionValidator(address(noSessionValidator)),
            salt: keccak256("failingSalt"),
            sessionValidatorInitData: "mockInitData",
            erc1271Policies: policyDatas,
            actions: new ActionData[](0)
        });

        // Enable session
        Session[] memory sessions = new Session[](1);
        sessions[0] = session;

        PermissionId[] memory permissionIds =
            smartSessionEmissary.enableSessions(sessions, env.lockTag, address(env.compact));

        defaultPermissionId = permissionIds[0];
    }

    function _createSmartSessionSignature(bytes32 digest) internal view returns (bytes memory) {
        // Create mock signature components (r, s, v)
        bytes32 r = bytes32(0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef);
        bytes32 s = bytes32(0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321);
        uint8 v = 27;

        // Construct the signature
        bytes memory sessionSignature = abi.encodePacked(
            r,
            s,
            v // Session validator signature
        );

        // Pack with SmartSession mode and permissionId
        return abi.encodePacked(
            EMISSARY_SMART_SESSION,
            defaultPermissionId,
            sessionSignature.length + 64,
            sessionSignature
        );
    }
}
