// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import {
    SmartSessionEmissary_Unit_Test
} from "@test/unit/SmartSessionEmissary/SmartSessionEmissary.t.sol";
import { Base_Test } from "@test/Base.t.sol";

// Contracts
import { MockAdapter } from "@mocks/MockAdapter.sol";
import { AlwaysOKAllocator } from "@the-compact/test/AlwaysOKAllocator.sol";
import {
    SmartSessionEmissaryMock as SmartSessionEmissary
} from "@mocks/SmartSessionEmissaryMock.sol";
import { MockTarget } from "@rhinestone/compact-utils/src/tests/MockTarget.sol";

// Libraries
import { TestHelperLib, CompactEnvironment } from "@compact-utils/tests/Environment.sol";
import { SmartExecutionLib } from "@rhinestone/compact-utils/src/common/SmartExecutionLib.sol";

// Interfaces
import { ISessionValidator } from "@smartsessions/interfaces/ISessionValidator.sol";

// Types
import {
    Element,
    Mandate,
    Target,
    MultichainCompact
} from "@compact-utils/types/TheCompactStructs.sol";
import { Execution } from "modulekit/integrations/ERC7579Exec.sol";
import { Types } from "@compact-utils/types/OrderTypes.sol";
import {
    PolicyData,
    ActionData,
    PermissionId,
    ERC7739Data,
    SmartSessionMode
} from "@smartsessions/DataTypes.sol";
import { Session } from "@types/DataTypes.sol";
import { EmissaryMode, EMISSARY_SMART_SESSION } from "@lib/ModeLib.sol";

/// @title SmartSessionEmissary Integration Test
/// @notice Integration tests for SmartSessionEmissary signature validation modes
/// @dev Tests verifyClaim (EMISSARY mode) and verifyExecution (EMISSARY_EXECUTION mode)
contract SmartSessionEmissary_Integration_Test is
    CompactEnvironment,
    SmartSessionEmissary_Unit_Test
{
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using TestHelperLib for *;

    /*//////////////////////////////////////////////////////////////
                                VARIABLES
    //////////////////////////////////////////////////////////////*/

    struct UserIntent {
        MultichainCompact compact;
        bytes32[] elementHashes;
        bytes32 claimHash;
        bytes32 digest;
        bytes userEmissarySig;
    }

    UserIntent $intent;
    PermissionId defaultPermissionId;
    MockAdapter mockAdapter;
    address arbiter;
    bytes12 testLockTag;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override(SmartSessionEmissary_Unit_Test) {
        // Deploy compact infrastructure
        _deployCompact();
        _deploySmartAccount({ create: true });
        _lockAssets(env.smartAccount1, env.token1, 100 ether);

        // Deploy MockAdapter
        mockAdapter =
            new MockAdapter(address(env.router), address(env.compact), address(ADDRESSBOOK));
        arbiter = address(mockAdapter);

        _setClaimRoute(MockAdapter.mock_compact_handleClaim.selector, address(mockAdapter));

        address recipient = env.smartAccount1.account;
        uint256 notarizedChain = chains.originChain1;

        $intent.compact.sponsor = env.smartAccount1.account;
        $intent.compact.nonce = 1337;
        $intent.compact.expires = block.timestamp + 1 hours;

        // Element 0: Uses EMISSARY sig mode (verifyClaim)
        $intent.compact.elements
            .push(
                Element({
                    arbiter: arbiter,
                    chainId: notarizedChain,
                    idsAndAmounts: [toId(env.token1), 100 ether].into(),
                    mandate: Mandate({
                        target: Target({
                            recipient: recipient,
                            tokenOut: [toId(env.token2), 20 ether].into(),
                            targetChain: notarizedChain,
                            fillExpiry: uint32(block.timestamp + 1 hours)
                        }),
                        minGas: 0,
                        originOps: intent.noExec.toOperation(), // No ops - uses default EMISSARY
                        // mode
                        destOps: intent.noExec.toOperation(),
                        q: ""
                    })
                })
            );

        ($intent.claimHash, $intent.elementHashes) = hashCompact(arbiter, $intent.compact);
        $intent.digest = _hashTypedData(notarizedChain, $intent.claimHash);

        env.alwaysOKAllocator = new AlwaysOKAllocator();
        vm.prank(address(env.alwaysOKAllocator));
        env.compact.__registerAllocator(address(env.alwaysOKAllocator), "");

        // Call Base_Test setup
        Base_Test.setUp();

        // Redeploy SmartSessionEmissary with intentExecutor in constructor
        smartSessionEmissary = new SmartSessionEmissary(address(env.intentExecutor));

        // Setup lockTag
        testLockTag = env.lockTag;

        // Setup SmartSessionEmissary as the emissary for the account
        vm.prank(env.smartAccount1.account);
        env.compact.assignEmissary(testLockTag, address(smartSessionEmissary));
    }

    /*//////////////////////////////////////////////////////////////
                          VERIFY CLAIM TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test verifyClaim succeeds with valid signature (EMISSARY mode - no ops)
    /// @dev When originOps is empty (NO_OPS), the signature mode defaults and verifyClaim is called
    function test_integration_verifyClaim_emissaryMode_succeeds() public {
        // Arrange - setup session with sudo policy (no restrictions)
        _setupSessionWithSudoPolicy();

        Types.Order memory order = _getOrder($intent.compact, 0);
        vm.chainId(order.notarizedChainId);

        // Create signature - no policy data needed for sudo
        $intent.userEmissarySig = _createSmartSessionSignature("");

        (, bytes memory allocatorSig) =
            _allocatorSig(env.orchestrator, order.notarizedChainId, $intent.claimHash);

        (, bytes32[] memory otherElements) = $intent.elementHashes.withoutIndex(0);

        // Act
        uint256 gas = _claim(
            order.notarizedChainId,
            abi.encodePacked(env.solver.addr),
            abi.encodeCall(
                MockAdapter.mock_compact_handleClaim,
                (MockAdapter.ClaimDataCompact({
                        order: order,
                        userSigs: Types.Signatures($intent.userEmissarySig, ""),
                        otherElements: otherElements,
                        allocatorData: allocatorSig,
                        elementIndex: 0
                    }))
            )
        );

        // Assert
        assertTrue(gas > 0, "Claim should succeed with verifyClaim");
    }

    /// @notice Test verifyClaim fails with invalid permission
    function test_integration_verifyClaim_emissaryMode_revertsWhen_invalidPermission() public {
        // Arrange - setup session but use wrong permissionId
        _setupSessionWithSudoPolicy();

        Types.Order memory order = _getOrder($intent.compact, 0);
        vm.chainId(order.notarizedChainId);

        // Create signature with invalid permissionId
        PermissionId wrongPermissionId = PermissionId.wrap(bytes32(uint256(12_345)));
        $intent.userEmissarySig = _createSmartSessionSignatureWithPermission(wrongPermissionId, "");

        (, bytes memory allocatorSig) =
            _allocatorSig(env.orchestrator, order.notarizedChainId, $intent.claimHash);

        (, bytes32[] memory otherElements) = $intent.elementHashes.withoutIndex(0);

        // Act & Assert
        vm.expectRevert();
        _claim(
            order.notarizedChainId,
            abi.encodePacked(env.solver.addr),
            abi.encodeCall(
                MockAdapter.mock_compact_handleClaim,
                (MockAdapter.ClaimDataCompact({
                        order: order,
                        userSigs: Types.Signatures($intent.userEmissarySig, ""),
                        otherElements: otherElements,
                        allocatorData: allocatorSig,
                        elementIndex: 0
                    }))
            )
        );
    }

    /*//////////////////////////////////////////////////////////////
                       VERIFY EXECUTION TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test verifyExecution succeeds with EMISSARY_EXECUTION sig mode
    /// @dev When originOps has ERC7579 executions with EMISSARY_EXECUTION mode, verifyExecution is
    /// called
    function test_integration_verifyExecution_emissaryExecutionMode_succeeds() public {
        // Arrange - create element with EMISSARY_EXECUTION sig mode
        _setupElementWithEmissaryExecutionMode();
        _setupSessionWithSudoExecutionPolicy();

        Types.Order memory order = _getOrder($intent.compact, 0);
        vm.chainId(order.notarizedChainId);

        $intent.userEmissarySig = _createVerifyExecutionSmartSessionSignature("");

        (, bytes memory allocatorSig) =
            _allocatorSig(env.orchestrator, order.notarizedChainId, $intent.claimHash);

        (, bytes32[] memory otherElements) = $intent.elementHashes.withoutIndex(0);

        // Act
        uint256 gas = _claim(
            order.notarizedChainId,
            abi.encodePacked(env.solver.addr),
            abi.encodeCall(
                MockAdapter.mock_compact_handleClaim,
                (MockAdapter.ClaimDataCompact({
                        order: order,
                        userSigs: Types.Signatures($intent.userEmissarySig, ""),
                        otherElements: otherElements,
                        allocatorData: allocatorSig,
                        elementIndex: 0
                    }))
            )
        );

        // Assert
        assertTrue(gas > 0, "Claim should succeed with verifyExecution");
        assertEq(env.target.param(), 42, "PreClaimOps should have executed targetFn(42)");
    }

    /// @notice Test verifyExecution fails with invalid permission
    function test_integration_verifyExecution_emissaryExecutionMode_revertsWhen_invalidPermission()
        public
    {
        // Arrange
        _setupElementWithEmissaryExecutionMode();
        _setupSessionWithSudoPolicy();

        Types.Order memory order = _getOrder($intent.compact, 0);
        vm.chainId(order.notarizedChainId);

        // Use wrong permissionId
        PermissionId wrongPermissionId = PermissionId.wrap(bytes32(uint256(99_999)));
        $intent.userEmissarySig =
            _createVerifyExecutionSmartSessionSignatureWithPermission(wrongPermissionId, "");

        (, bytes memory allocatorSig) =
            _allocatorSig(env.orchestrator, order.notarizedChainId, $intent.claimHash);

        (, bytes32[] memory otherElements) = $intent.elementHashes.withoutIndex(0);

        // Act & Assert
        vm.expectRevert();
        _claim(
            order.notarizedChainId,
            abi.encodePacked(env.solver.addr),
            abi.encodeCall(
                MockAdapter.mock_compact_handleClaim,
                (MockAdapter.ClaimDataCompact({
                        order: order,
                        userSigs: Types.Signatures($intent.userEmissarySig, ""),
                        otherElements: otherElements,
                        allocatorData: allocatorSig,
                        elementIndex: 0
                    }))
            )
        );
    }

    /// @notice Test verifyExecution with action policies
    /// @dev Tests that action policies are checked during verifyExecution
    function test_integration_verifyExecution_withActionPolicy_succeeds() public {
        // Arrange - create element with specific execution target
        _setupElementWithEmissaryExecutionMode();

        // Setup session with action policy that allows the target
        address allowedTarget = address(env.target);
        _setupSessionWithActionPolicy(allowedTarget);

        Types.Order memory order = _getOrder($intent.compact, 0);
        vm.chainId(order.notarizedChainId);

        $intent.userEmissarySig = _createVerifyExecutionSmartSessionSignature("");

        (, bytes memory allocatorSig) =
            _allocatorSig(env.orchestrator, order.notarizedChainId, $intent.claimHash);

        (, bytes32[] memory otherElements) = $intent.elementHashes.withoutIndex(0);

        // Act
        uint256 gas = _claim(
            order.notarizedChainId,
            abi.encodePacked(env.solver.addr),
            abi.encodeCall(
                MockAdapter.mock_compact_handleClaim,
                (MockAdapter.ClaimDataCompact({
                        order: order,
                        userSigs: Types.Signatures($intent.userEmissarySig, ""),
                        otherElements: otherElements,
                        allocatorData: allocatorSig,
                        elementIndex: 0
                    }))
            )
        );

        assertTrue(gas > 0, "Claim should succeed with action policy");
        assertEq(env.target.param(), 42, "PreClaimOps should have executed targetFn(42)");
    }

    /*//////////////////////////////////////////////////////////////
                     ERC1271_EMISSARY FALLBACK TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test ERC1271_EMISSARY mode falls back to emissary when ERC1271 fails
    function test_integration_erc1271EmissaryMode_fallbackToEmissary_succeeds() public {
        // Arrange - create element with ERC1271_EMISSARY sig mode
        _setupElementWithErc1271EmissaryMode();
        _setupSessionWithSudoPolicy();

        Types.Order memory order = _getOrder($intent.compact, 0);
        vm.chainId(order.notarizedChainId);

        // Use emissary signature format (not raw ERC1271)
        $intent.userEmissarySig = _createSmartSessionSignature("");

        (, bytes memory allocatorSig) =
            _allocatorSig(env.orchestrator, order.notarizedChainId, $intent.claimHash);

        (, bytes32[] memory otherElements) = $intent.elementHashes.withoutIndex(0);

        // Act - should succeed via emissary fallback
        uint256 gas = _claim(
            order.notarizedChainId,
            abi.encodePacked(env.solver.addr),
            abi.encodeCall(
                MockAdapter.mock_compact_handleClaim,
                (MockAdapter.ClaimDataCompact({
                        order: order,
                        userSigs: Types.Signatures($intent.userEmissarySig, ""),
                        otherElements: otherElements,
                        allocatorData: allocatorSig,
                        elementIndex: 0
                    }))
            )
        );

        assertTrue(gas > 0, "Claim should succeed via emissary fallback");
    }

    /*//////////////////////////////////////////////////////////////
                        ELEMENT SETUP HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Setup element with EMISSARY_EXECUTION sig mode
    function _setupElementWithEmissaryExecutionMode() internal {
        // Create executions - use a real function from MockTarget
        Execution[] memory executions = new Execution[](1);
        executions[0] = Execution({
            target: address(env.target),
            value: 0,
            callData: abi.encodeCall(MockTarget.targetFn, (42)) // Real function!
        });

        // Update element 0 with EMISSARY_EXECUTION mode
        $intent.compact.elements[0].mandate.originOps =
            TestHelperLib.toOperation(executions, SmartExecutionLib.SigMode.EMISSARY_EXECUTION);

        // Recompute hashes
        ($intent.claimHash, $intent.elementHashes) = hashCompact(arbiter, $intent.compact);
        $intent.digest = _hashTypedData(chains.originChain1, $intent.claimHash);
    }

    /// @notice Setup element with ERC1271_EMISSARY sig mode
    function _setupElementWithErc1271EmissaryMode() internal {
        // Create executions - use a real function from MockTarget
        Execution[] memory executions = new Execution[](1);
        executions[0] = Execution({
            target: address(env.target),
            value: 0,
            callData: abi.encodeCall(MockTarget.targetFn, (42)) // Real function!
        });

        // Update element 0 with ERC1271_EMISSARY mode
        $intent.compact.elements[0].mandate.originOps =
            TestHelperLib.toOperation(executions, SmartExecutionLib.SigMode.ERC1271_EMISSARY);

        // Recompute hashes
        ($intent.claimHash, $intent.elementHashes) = hashCompact(arbiter, $intent.compact);
        $intent.digest = _hashTypedData(chains.originChain1, $intent.claimHash);
    }

    /*//////////////////////////////////////////////////////////////
                         SESSION SETUP HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Setup session with sudo policy for claims (no restrictions)
    function _setupSessionWithSudoPolicy() internal {
        vm.prank(env.smartAccount1.account);

        // Need at least one claim policy - use sudoPolicy for no restrictions
        PolicyData[] memory claimPolicies = new PolicyData[](1);
        claimPolicies[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });

        ERC7739Data memory erc7739Data;

        Session memory session = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: keccak256(abi.encodePacked("sudoSalt", block.timestamp)),
            sessionValidatorInitData: "mockInitData",
            erc7739Policies: erc7739Data,
            actions: new ActionData[](0),
            claimPolicies: claimPolicies
        });

        Session[] memory sessions = new Session[](1);
        sessions[0] = session;
        PermissionId[] memory permissionIds =
            smartSessionEmissary.enableSessions(sessions, testLockTag);
        defaultPermissionId = permissionIds[0];
    }

    /// @notice Setup session with sudo policy for executions (includes claim policies for fallback)
    function _setupSessionWithSudoExecutionPolicy() internal {
        vm.prank(env.smartAccount1.account);

        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });

        // For verifyExecution, we need action policies with the correct selector
        ActionData[] memory actions = new ActionData[](1);
        actions[0] = ActionData({
            actionTarget: address(env.target),
            actionTargetSelector: MockTarget.targetFn.selector, // Use actual selector!
            actionPolicies: policyDatas
        });

        ERC7739Data memory erc7739Data;

        Session memory session = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: keccak256(abi.encodePacked("sudoExecSalt", block.timestamp)),
            sessionValidatorInitData: "mockInitData",
            erc7739Policies: erc7739Data,
            actions: actions,
            claimPolicies: policyDatas // Also add claim policies for the claim step!
        });

        Session[] memory sessions = new Session[](1);
        sessions[0] = session;
        PermissionId[] memory permissionIds =
            smartSessionEmissary.enableSessions(sessions, testLockTag);
        defaultPermissionId = permissionIds[0];
    }

    /// @notice Setup session with action policy for specific target
    function _setupSessionWithActionPolicy(address allowedTarget) internal {
        vm.prank(env.smartAccount1.account);

        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });

        // Create action data that allows calls to the target
        ActionData[] memory actions = new ActionData[](1);
        actions[0] = ActionData({
            actionTargetSelector: MockTarget.targetFn.selector, // Use actual selector!
            actionTarget: allowedTarget,
            actionPolicies: policyDatas
        });

        ERC7739Data memory erc7739Data;

        Session memory session = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: keccak256(abi.encodePacked("actionPolicySalt", block.timestamp)),
            sessionValidatorInitData: "mockInitData",
            erc7739Policies: erc7739Data,
            actions: actions,
            claimPolicies: policyDatas // Also add claim policies!
        });

        Session[] memory sessions = new Session[](1);
        sessions[0] = session;
        PermissionId[] memory permissionIds =
            smartSessionEmissary.enableSessions(sessions, testLockTag);
        defaultPermissionId = permissionIds[0];
    }

    /*//////////////////////////////////////////////////////////////
                         SIGNATURE HELPERS
    //////////////////////////////////////////////////////////////*/

    function _createSmartSessionSignature(bytes memory policyData)
        internal
        view
        returns (bytes memory)
    {
        return _createSmartSessionSignatureWithPermission(defaultPermissionId, policyData);
    }

    function _createVerifyExecutionSmartSessionSignature(bytes memory policyData)
        internal
        view
        returns (bytes memory)
    {
        return _createVerifyExecutionSmartSessionSignatureWithPermission(
            defaultPermissionId, policyData
        );
    }

    function _createVerifyExecutionSmartSessionSignatureWithPermission(
        PermissionId permissionId,
        bytes memory policyData
    )
        internal
        pure
        returns (bytes memory)
    {
        bytes32 r = bytes32(0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef);
        bytes32 s = bytes32(0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321);
        uint8 v = 27;

        bytes memory sessionValidatorSignature = abi.encodePacked(r, s, v);

        return abi.encodePacked(
            EMISSARY_SMART_SESSION,
            SmartSessionMode.USE,
            permissionId,
            uint256(sessionValidatorSignature.length) + 64,
            sessionValidatorSignature,
            policyData
        );
    }

    function _createSmartSessionSignatureWithPermission(
        PermissionId permissionId,
        bytes memory policyData
    )
        internal
        pure
        returns (bytes memory)
    {
        bytes32 r = bytes32(0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef);
        bytes32 s = bytes32(0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321);
        uint8 v = 27;

        bytes memory sessionValidatorSignature = abi.encodePacked(r, s, v);

        return abi.encodePacked(
            EMISSARY_SMART_SESSION,
            permissionId,
            uint256(sessionValidatorSignature.length) + 64,
            sessionValidatorSignature,
            policyData
        );
    }
}
