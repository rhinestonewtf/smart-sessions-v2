// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import {
    SmartSessionEmissary_Unit_Test
} from "@test/unit/SmartSessionEmissary/SmartSessionEmissary.t.sol";

// Contracts
import { MockAdapter } from "@mocks/MockAdapter.sol";
import { AlwaysOKAllocator } from "@the-compact/test/AlwaysOKAllocator.sol";
import { CompactClaimPolicy } from "@policies/claim/compact/CompactClaimPolicy.sol";

// Libraries
import { IdLib } from "@the-compact/lib/IdLib.sol";
import { ModuleKitHelpers } from "@modulekit/ModuleKit.sol";
import { TestHelperLib, CompactEnvironment } from "@compact-utils/tests/Environment.sol";
import { HashLib } from "@smartsessions/lib/HashLib.sol";
import { EIP712TypeHashLib } from "@compact-utils/types/EIP712TypeHashLib.sol";

// Interfaces
import { ISessionValidator } from "@smartsessions/interfaces/ISessionValidator.sol";

// Types
import {
    Element,
    Mandate,
    Target,
    MultichainCompact
} from "@compact-utils/types/TheCompactStructs.sol";
import { Execution } from "@smartsessions/lib/ExecutionLib.sol";
import { Types } from "@compact-utils/types/OrderTypes.sol";
import { PolicyData, ActionData, PermissionId, ERC7739Data } from "@smartsessions/DataTypes.sol";
import { Session } from "@types/DataTypes.sol";
import { EmissaryMode, EMISSARY_SMART_SESSION } from "@lib/ModeLib.sol";
import {
    FIELD_ARBITER,
    FIELD_ORIGIN_OPS,
    FIELD_RECIPIENT_IS_SPONSOR,
    FIELD_TOKEN_IN,
    FIELD_RECIPIENT,
    FIELD_TOKEN_OUT,
    MODE_CHECK_STORAGE
} from "@policies/claim/base/types/BaseDataTypes.sol";

/// @title CompactClaimPolicy Integration Test
/// @notice Integration tests for CompactClaimPolicy validation via SmartSessionEmissary
contract CompactClaimPolicy_Integration_Test is CompactEnvironment, SmartSessionEmissary_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using TestHelperLib for *;
    using IdLib for *;

    /*//////////////////////////////////////////////////////////////
                                VARIABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice Intent struct to hold all claim-related data
    struct UserIntent {
        MultichainCompact compact;
        bytes32[] elementHashes;
        bytes32 claimHash;
        bytes32 digest;
        bytes userEmissarySig;
    }

    UserIntent $intent;
    PermissionId defaultPermissionId;
    CompactClaimPolicy compactClaimPolicy;
    bytes12 testLockTag;
    MockAdapter mockAdapter;
    address arbiter;
    uint8 internal activeFieldMode;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override(SmartSessionEmissary_Unit_Test) {
        // Deploy compact infrastructure
        _deployCompact();
        _deploySmartAccount({ create: true });
        _lockAssets(env.smartAccount1, env.token1, 100 ether);

        // Deploy MockAdapter for both notarized and exogenous chain tests
        mockAdapter =
            new MockAdapter(address(env.router), address(env.compact), address(ADDRESSBOOK));
        arbiter = address(mockAdapter);

        _setClaimRoute(MockAdapter.mock_compact_handleClaim.selector, address(mockAdapter));
        _sampleExecERC20(env.token2, 10);

        address recipient = env.smartAccount1.account;

        $intent.compact.sponsor = env.smartAccount1.account;
        $intent.compact.nonce = 1337;
        $intent.compact.expires = 4141;

        uint256 notarizedChain = chains.originChain1;

        // Element 0: Notarized chain (originChain1) - HAS executions
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
                        minGas: 0,
                        originOps: intent.targetExecutions.toOperation(),
                        destOps: intent.targetExecutions.toOperation(),
                        q: ""
                    })
                })
            );

        // Element 1: Exogenous chain (originChain2) - NO executions
        $intent.compact.elements
            .push(
                Element({
                    arbiter: arbiter,
                    chainId: chains.originChain2,
                    idsAndAmounts: [toId(env.token1), 50].into(),
                    mandate: Mandate({
                        target: Target({
                            recipient: recipient,
                            tokenOut: [toId(env.token2), 10].into(),
                            targetChain: chains.originChain2,
                            fillExpiry: uint32(block.timestamp + 1 hours)
                        }),
                        minGas: 0,
                        originOps: intent.noExec.toOperation(),
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

        // Call SmartSessionEmissary setup
        SmartSessionEmissary_Unit_Test.setUp();

        // Deploy CompactClaimPolicy
        compactClaimPolicy = new CompactClaimPolicy();

        // Setup lockTag
        testLockTag = env.lockTag;

        // Setup SmartSessionEmissary as the emissary for the account
        vm.prank(env.smartAccount1.account);
        env.compact.assignEmissary(testLockTag, address(smartSessionEmissary));
    }

    /*//////////////////////////////////////////////////////////////
                               ORIGIN OPS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test hasExecutions passes on notarized chain (element 0 has executions)
    function test_integration_verifyClaim_compact_hasExecutions_notarizedChain() public {
        // Arrange
        _setupSessionWithOriginOPsConfig({ required: true });

        Types.Order memory order = _getOrder($intent.compact, 0);
        vm.chainId(order.notarizedChainId);

        bytes memory policyData = _createPolicyDataForElement(0);
        $intent.userEmissarySig = _createSmartSessionSignature(policyData);

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
        assertTrue(gas > 0, "Claim should succeed - element 0 has executions");
    }

    /// @notice Test hasExecutions fails on exogenous chain (element 1 has NO executions)
    function test_integration_verifyClaim_compact_hasExecutions_revertsWhen_noExecutions() public {
        Types.Order memory order = _getOrder($intent.compact, 1);
        uint256 exogenousChainId = $intent.compact.elements[1].chainId;
        vm.chainId(exogenousChainId);

        // Arrange - require executions but element 1 has none
        _setupSessionWithOriginOPsConfig({ required: true });

        bytes memory policyData = _createPolicyDataForElement(1);
        $intent.userEmissarySig = _createSmartSessionSignature(policyData);

        (, bytes memory allocatorSig) =
            _allocatorSig(env.orchestrator, exogenousChainId, $intent.claimHash);

        (uint256 chainIndex, bytes32[] memory otherElements) = $intent.elementHashes.withoutIndex(1);

        // Act & Assert - should fail because element 1 has no executions
        vm.expectRevert();
        _claim(
            exogenousChainId,
            abi.encodePacked(env.solver.addr),
            abi.encodeCall(
                MockAdapter.mock_compact_handleClaim,
                (MockAdapter.ClaimDataCompact({
                        order: order,
                        userSigs: Types.Signatures($intent.userEmissarySig, ""),
                        otherElements: otherElements,
                        allocatorData: allocatorSig,
                        elementIndex: chainIndex
                    }))
            )
        );
    }

    /// @notice Test hasExecutions passes when NOT required and element has no executions
    function test_integration_verifyClaim_compact_hasExecutions_notRequired() public {
        Types.Order memory order = _getOrder($intent.compact, 1);
        uint256 exogenousChainId = $intent.compact.elements[1].chainId;
        vm.chainId(exogenousChainId);

        // Arrange - do NOT require executions
        _setupSessionWithOriginOPsConfig({ required: false });

        bytes memory policyData = _createPolicyDataForElement(1);
        $intent.userEmissarySig = _createSmartSessionSignature(policyData);

        (, bytes memory allocatorSig) =
            _allocatorSig(env.orchestrator, exogenousChainId, $intent.claimHash);

        (uint256 chainIndex, bytes32[] memory otherElements) = $intent.elementHashes.withoutIndex(1);

        // Act
        uint256 gas = _claim(
            exogenousChainId,
            abi.encodePacked(env.solver.addr),
            abi.encodeCall(
                MockAdapter.mock_compact_handleClaim,
                (MockAdapter.ClaimDataCompact({
                        order: order,
                        userSigs: Types.Signatures($intent.userEmissarySig, ""),
                        otherElements: otherElements,
                        allocatorData: allocatorSig,
                        elementIndex: chainIndex
                    }))
            )
        );

        // Assert
        assertTrue(gas > 0, "Fill should succeed - executions not required");
    }

    /*//////////////////////////////////////////////////////////////
                                TOKEN IN
    //////////////////////////////////////////////////////////////*/

    /// @notice Test tokenIn validation on notarized chain
    function test_integration_verifyClaim_compact_tokenIn_notarizedChain() public {
        // Arrange - configure for element 0's token (100 amount)
        _setupSessionWithTokenInConfig({ chainId: chains.originChain1, token: address(env.token1) });

        Types.Order memory order = _getOrder($intent.compact, 0);
        vm.chainId(order.notarizedChainId);

        bytes memory policyData = _createPolicyDataForElement(0);
        $intent.userEmissarySig = _createSmartSessionSignature(policyData);

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

        assertTrue(gas > 0, "Fill should succeed - tokenIn within range");
    }

    /// @notice Test tokenIn validation on exogenous chain
    function test_integration_verifyClaim_compact_tokenIn_exogenousChain() public {
        // Arrange - configure for element 1's chain and token (50 amount)
        _setupSessionWithTokenInConfig({ chainId: chains.originChain2, token: address(env.token1) });

        Types.Order memory order = _getOrder($intent.compact, 1);
        uint256 exogenousChainId = $intent.compact.elements[1].chainId;

        vm.chainId(exogenousChainId);

        bytes memory policyData = _createPolicyDataForElement(1);
        $intent.userEmissarySig = _createSmartSessionSignature(policyData);

        (, bytes memory allocatorSig) =
            _allocatorSig(env.orchestrator, exogenousChainId, $intent.claimHash);

        (uint256 chainIndex, bytes32[] memory otherElements) = $intent.elementHashes.withoutIndex(1);

        // Act
        uint256 gas = _claim(
            exogenousChainId,
            abi.encodePacked(env.solver.addr),
            abi.encodeCall(
                MockAdapter.mock_compact_handleClaim,
                (MockAdapter.ClaimDataCompact({
                        order: order,
                        userSigs: Types.Signatures($intent.userEmissarySig, ""),
                        otherElements: otherElements,
                        allocatorData: allocatorSig,
                        elementIndex: chainIndex
                    }))
            )
        );

        assertTrue(gas > 0, "Fill should succeed on exogenous chain");
    }

    /// @notice Test tokenIn validation fails when wrong token
    function test_integration_verifyClaim_compact_tokenIn_revertsWhen_wrongToken() public {
        // Arrange - configure for token2 but element 0 uses token1
        _setupSessionWithTokenInConfig({ chainId: chains.originChain1, token: address(env.token2) });

        Types.Order memory order = _getOrder($intent.compact, 0);
        vm.chainId(order.notarizedChainId);

        bytes memory policyData = _createPolicyDataForElement(0);
        $intent.userEmissarySig = _createSmartSessionSignature(policyData);

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

    /// @notice Test tokenIn config for chain1 doesn't work on chain2
    function test_integration_verifyClaim_compact_tokenIn_revertsWhen_noConfigForChain() public {
        // Arrange - configure tokenIn ONLY for chain 1
        _setupSessionWithTokenInConfig({ chainId: chains.originChain1, token: address(env.token1) });

        // Try to claim on chain 2 - should fail because no config for chain 2
        Types.Order memory order = _getOrder($intent.compact, 1);
        uint256 exogenousChainId = $intent.compact.elements[1].chainId;

        vm.chainId(exogenousChainId);

        bytes memory policyData = _createPolicyDataForElement(1);
        $intent.userEmissarySig = _createSmartSessionSignature(policyData);

        (, bytes memory allocatorSig) =
            _allocatorSig(env.orchestrator, exogenousChainId, $intent.claimHash);

        (, bytes32[] memory otherElements) = $intent.elementHashes.withoutIndex(1);

        // Act & Assert - should fail, tokenIn not configured for chain 2
        vm.expectRevert();
        _claim(
            exogenousChainId,
            abi.encodePacked(env.solver.addr),
            abi.encodeCall(
                MockAdapter.mock_compact_handleClaim,
                (MockAdapter.ClaimDataCompact({
                        order: order,
                        userSigs: Types.Signatures($intent.userEmissarySig, ""),
                        otherElements: otherElements,
                        allocatorData: allocatorSig,
                        elementIndex: 1
                    }))
            )
        );
    }

    /*//////////////////////////////////////////////////////////////
                                ARBITER
    //////////////////////////////////////////////////////////////*/

    /// @notice Test arbiter validation succeeds with correct arbiter
    function test_integration_verifyClaim_compact_arbiter_notarizedChain() public {
        // Arrange
        _setupSessionWithArbiterConfig(arbiter);

        Types.Order memory order = _getOrder($intent.compact, 0);
        vm.chainId(order.notarizedChainId);

        bytes memory policyData = _createPolicyDataForElement(0);
        $intent.userEmissarySig = _createSmartSessionSignature(policyData);

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

        assertTrue(gas > 0, "Fill should succeed with correct arbiter");
    }

    /// @notice Test arbiter validation succeeds on exogenous chain
    function test_integration_verifyClaim_compact_arbiter_exogenousChain() public {
        // Arrange
        _setupSessionWithArbiterConfig(arbiter);

        Types.Order memory order = _getOrder($intent.compact, 1);
        uint256 exogenousChainId = $intent.compact.elements[1].chainId;

        vm.chainId(exogenousChainId);

        bytes memory policyData = _createPolicyDataForElement(1);
        $intent.userEmissarySig = _createSmartSessionSignature(policyData);

        (, bytes memory allocatorSig) =
            _allocatorSig(env.orchestrator, exogenousChainId, $intent.claimHash);

        (uint256 chainIndex, bytes32[] memory otherElements) = $intent.elementHashes.withoutIndex(1);

        // Act
        uint256 gas = _claim(
            exogenousChainId,
            abi.encodePacked(env.solver.addr),
            abi.encodeCall(
                MockAdapter.mock_compact_handleClaim,
                (MockAdapter.ClaimDataCompact({
                        order: order,
                        userSigs: Types.Signatures($intent.userEmissarySig, ""),
                        otherElements: otherElements,
                        allocatorData: allocatorSig,
                        elementIndex: chainIndex
                    }))
            )
        );

        assertTrue(gas > 0, "Fill should succeed with correct arbiter on exogenous chain");
    }

    /// @notice Test arbiter validation fails with wrong arbiter
    function test_integration_verifyClaim_compact_arbiter_revertsWhen_wrongArbiter() public {
        // Arrange - configure wrong arbiter
        address wrongArbiter = makeAddr("wrongArbiter");
        _setupSessionWithArbiterConfig(wrongArbiter);

        Types.Order memory order = _getOrder($intent.compact, 0);
        vm.chainId(order.notarizedChainId);

        bytes memory policyData = _createPolicyDataForElement(0);
        $intent.userEmissarySig = _createSmartSessionSignature(policyData);

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
                               RECIPIENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Test recipient validation on notarized chain
    function test_integration_verifyClaim_compact_recipient_notarizedChain() public {
        // Arrange - configure for element 0's recipient
        address recipient = env.smartAccount1.account;
        _setupSessionWithRecipientConfig({ chainId: chains.originChain1, recipient: recipient });

        Types.Order memory order = _getOrder($intent.compact, 0);
        vm.chainId(order.notarizedChainId);

        bytes memory policyData = _createPolicyDataForElement(0);
        $intent.userEmissarySig = _createSmartSessionSignature(policyData);

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

        assertTrue(gas > 0, "Claim should succeed - recipient matches");
    }

    /// @notice Test recipient validation on exogenous chain
    function test_integration_verifyClaim_compact_recipient_exogenousChain() public {
        // Arrange - configure for element 1's chain and recipient
        address recipient = env.smartAccount1.account;
        _setupSessionWithRecipientConfig({ chainId: chains.originChain2, recipient: recipient });

        Types.Order memory order = _getOrder($intent.compact, 1);
        uint256 exogenousChainId = $intent.compact.elements[1].chainId;

        vm.chainId(exogenousChainId);

        bytes memory policyData = _createPolicyDataForElement(1);
        $intent.userEmissarySig = _createSmartSessionSignature(policyData);

        (, bytes memory allocatorSig) =
            _allocatorSig(env.orchestrator, exogenousChainId, $intent.claimHash);

        (uint256 chainIndex, bytes32[] memory otherElements) = $intent.elementHashes.withoutIndex(1);

        // Act
        uint256 gas = _claim(
            exogenousChainId,
            abi.encodePacked(env.solver.addr),
            abi.encodeCall(
                MockAdapter.mock_compact_handleClaim,
                (MockAdapter.ClaimDataCompact({
                        order: order,
                        userSigs: Types.Signatures($intent.userEmissarySig, ""),
                        otherElements: otherElements,
                        allocatorData: allocatorSig,
                        elementIndex: chainIndex
                    }))
            )
        );

        assertTrue(gas > 0, "Claim should succeed on exogenous chain");
    }

    /// @notice Test recipient validation fails when wrong recipient
    function test_integration_verifyClaim_compact_recipient_revertsWhen_wrongRecipient() public {
        // Arrange - configure for different recipient than element 0 uses
        address wrongRecipient = makeAddr("wrongRecipient");
        _setupSessionWithRecipientConfig({
            chainId: chains.originChain1, recipient: wrongRecipient
        });

        Types.Order memory order = _getOrder($intent.compact, 0);
        vm.chainId(order.notarizedChainId);

        bytes memory policyData = _createPolicyDataForElement(0);
        $intent.userEmissarySig = _createSmartSessionSignature(policyData);

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

    /// @notice Test recipient config for chain1 doesn't work on chain2
    function test_integration_verifyClaim_compact_recipient_revertsWhen_noConfigForChain() public {
        // Arrange - configure recipient ONLY for chain 1
        address recipient = env.smartAccount1.account;
        _setupSessionWithRecipientConfig({ chainId: chains.originChain1, recipient: recipient });

        // Try to claim on chain 2 - should fail because no config for chain 2
        Types.Order memory order = _getOrder($intent.compact, 1);
        uint256 exogenousChainId = $intent.compact.elements[1].chainId;

        vm.chainId(exogenousChainId);

        bytes memory policyData = _createPolicyDataForElement(1);
        $intent.userEmissarySig = _createSmartSessionSignature(policyData);

        (, bytes memory allocatorSig) =
            _allocatorSig(env.orchestrator, exogenousChainId, $intent.claimHash);

        (, bytes32[] memory otherElements) = $intent.elementHashes.withoutIndex(1);

        // Act & Assert - should fail, recipient not configured for chain 2
        vm.expectRevert();
        _claim(
            exogenousChainId,
            abi.encodePacked(env.solver.addr),
            abi.encodeCall(
                MockAdapter.mock_compact_handleClaim,
                (MockAdapter.ClaimDataCompact({
                        order: order,
                        userSigs: Types.Signatures($intent.userEmissarySig, ""),
                        otherElements: otherElements,
                        allocatorData: allocatorSig,
                        elementIndex: 1
                    }))
            )
        );
    }

    /*//////////////////////////////////////////////////////////////
                               TOKEN OUT
    //////////////////////////////////////////////////////////////*/

    /// @notice Test tokenOut validation on notarized chain
    function test_integration_verifyClaim_compact_tokenOut_notarizedChain() public {
        // Arrange - configure for element 0's tokenOut
        _setupSessionWithTokenOutConfig({
            chainId: chains.originChain1, token: address(env.token2)
        });

        Types.Order memory order = _getOrder($intent.compact, 0);
        vm.chainId(order.notarizedChainId);

        bytes memory policyData = _createPolicyDataForElement(0);
        $intent.userEmissarySig = _createSmartSessionSignature(policyData);

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

        assertTrue(gas > 0, "Claim should succeed - tokenOut matches");
    }

    /// @notice Test tokenOut validation on exogenous chain
    function test_integration_verifyClaim_compact_tokenOut_exogenousChain() public {
        // Arrange - configure for element 1's chain and tokenOut
        _setupSessionWithTokenOutConfig({
            chainId: chains.originChain2, token: address(env.token2)
        });

        Types.Order memory order = _getOrder($intent.compact, 1);
        uint256 exogenousChainId = $intent.compact.elements[1].chainId;

        vm.chainId(exogenousChainId);

        bytes memory policyData = _createPolicyDataForElement(1);
        $intent.userEmissarySig = _createSmartSessionSignature(policyData);

        (, bytes memory allocatorSig) =
            _allocatorSig(env.orchestrator, exogenousChainId, $intent.claimHash);

        (uint256 chainIndex, bytes32[] memory otherElements) = $intent.elementHashes.withoutIndex(1);

        // Act
        uint256 gas = _claim(
            exogenousChainId,
            abi.encodePacked(env.solver.addr),
            abi.encodeCall(
                MockAdapter.mock_compact_handleClaim,
                (MockAdapter.ClaimDataCompact({
                        order: order,
                        userSigs: Types.Signatures($intent.userEmissarySig, ""),
                        otherElements: otherElements,
                        allocatorData: allocatorSig,
                        elementIndex: chainIndex
                    }))
            )
        );

        assertTrue(gas > 0, "Claim should succeed on exogenous chain");
    }

    /// @notice Test tokenOut validation fails when wrong token
    function test_integration_verifyClaim_compact_tokenOut_revertsWhen_wrongToken() public {
        // Arrange - configure for token1 but element 0 uses token2 as tokenOut
        _setupSessionWithTokenOutConfig({
            chainId: chains.originChain1, token: address(env.token1)
        });

        Types.Order memory order = _getOrder($intent.compact, 0);
        vm.chainId(order.notarizedChainId);

        bytes memory policyData = _createPolicyDataForElement(0);
        $intent.userEmissarySig = _createSmartSessionSignature(policyData);

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

    /// @notice Test tokenOut config for chain1 doesn't work on chain2
    function test_integration_verifyClaim_compact_tokenOut_revertsWhen_noConfigForChain() public {
        // Arrange - configure tokenOut ONLY for chain 1
        _setupSessionWithTokenOutConfig({
            chainId: chains.originChain1, token: address(env.token2)
        });

        // Try to claim on chain 2 - should fail because no config for chain 2
        Types.Order memory order = _getOrder($intent.compact, 1);
        uint256 exogenousChainId = $intent.compact.elements[1].chainId;

        vm.chainId(exogenousChainId);

        bytes memory policyData = _createPolicyDataForElement(1);
        $intent.userEmissarySig = _createSmartSessionSignature(policyData);

        (, bytes memory allocatorSig) =
            _allocatorSig(env.orchestrator, exogenousChainId, $intent.claimHash);

        (, bytes32[] memory otherElements) = $intent.elementHashes.withoutIndex(1);

        // Act & Assert - should fail, tokenOut not configured for chain 2
        vm.expectRevert();
        _claim(
            exogenousChainId,
            abi.encodePacked(env.solver.addr),
            abi.encodeCall(
                MockAdapter.mock_compact_handleClaim,
                (MockAdapter.ClaimDataCompact({
                        order: order,
                        userSigs: Types.Signatures($intent.userEmissarySig, ""),
                        otherElements: otherElements,
                        allocatorData: allocatorSig,
                        elementIndex: 1
                    }))
            )
        );
    }

    /*//////////////////////////////////////////////////////////////
                          RECIPIENT IS SPONSOR
    //////////////////////////////////////////////////////////////*/

    /// @notice Test recipientIsSponsor passes when recipient equals sponsor
    function test_integration_verifyClaim_compact_recipientIsSponsor_notarizedChain() public {
        // Arrange - element 0's recipient is already env.smartAccount1.account (the sponsor)
        _setupSessionWithRecipientIsSponsorConfig();

        Types.Order memory order = _getOrder($intent.compact, 0);
        vm.chainId(order.notarizedChainId);

        bytes memory policyData = _createPolicyDataForElement(0);
        $intent.userEmissarySig = _createSmartSessionSignature(policyData);

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

        assertTrue(gas > 0, "Claim should succeed - recipient is sponsor");
    }

    /// @notice Test recipientIsSponsor passes on exogenous chain
    function test_integration_verifyClaim_compact_recipientIsSponsor_exogenousChain() public {
        // Arrange - element 1's recipient is also env.smartAccount1.account
        _setupSessionWithRecipientIsSponsorConfig();

        Types.Order memory order = _getOrder($intent.compact, 1);
        uint256 exogenousChainId = $intent.compact.elements[1].chainId;

        vm.chainId(exogenousChainId);

        bytes memory policyData = _createPolicyDataForElement(1);
        $intent.userEmissarySig = _createSmartSessionSignature(policyData);

        (, bytes memory allocatorSig) =
            _allocatorSig(env.orchestrator, exogenousChainId, $intent.claimHash);

        (uint256 chainIndex, bytes32[] memory otherElements) = $intent.elementHashes.withoutIndex(1);

        // Act
        uint256 gas = _claim(
            exogenousChainId,
            abi.encodePacked(env.solver.addr),
            abi.encodeCall(
                MockAdapter.mock_compact_handleClaim,
                (MockAdapter.ClaimDataCompact({
                        order: order,
                        userSigs: Types.Signatures($intent.userEmissarySig, ""),
                        otherElements: otherElements,
                        allocatorData: allocatorSig,
                        elementIndex: chainIndex
                    }))
            )
        );

        assertTrue(gas > 0, "Claim should succeed on exogenous chain");
    }

    /// @notice Test recipientIsSponsor fails when recipient is not sponsor
    function test_integration_verifyClaim_compact_recipientIsSponsor_revertsWhen_notSponsor()
        public
    {
        // Arrange - modify element 0 to have different recipient
        address differentRecipient = makeAddr("differentRecipient");
        $intent.compact.elements[0].mandate.target.recipient = differentRecipient;

        // Recompute hashes after modification
        ($intent.claimHash, $intent.elementHashes) = hashCompact(arbiter, $intent.compact);

        _setupSessionWithRecipientIsSponsorConfig();

        Types.Order memory order = _getOrder($intent.compact, 0);
        vm.chainId(order.notarizedChainId);

        bytes memory policyData = _createPolicyDataForElement(0);
        $intent.userEmissarySig = _createSmartSessionSignature(policyData);

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
                         SESSION SETUP HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Setup session with originOps (hasExecutions) check
    /// @dev originOps config format: [count: 1][chainId: 32][required: 1]
    function _setupSessionWithOriginOPsConfig(bool required) internal {
        // Set active mode for policy data generation
        activeFieldMode = FIELD_ORIGIN_OPS;

        vm.prank(env.smartAccount1.account);

        // Create modeConfig with FIELD_ORIGIN_OPS enabled
        uint32 modeConfig = _createModeConfig(FIELD_ORIGIN_OPS, MODE_CHECK_STORAGE);

        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({
            policy: address(compactClaimPolicy),
            initData: abi.encodePacked(
                modeConfig, // 4 bytes - mode configuration
                uint8(1), // 1 byte  - count of entries
                uint256(block.chainid), // 32 bytes - chainId
                uint8(required ? 1 : 0) // 1 byte  - required flag
            )
        });

        ERC7739Data memory erc7739Data;

        Session memory session = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: keccak256(abi.encodePacked("hasExecSalt", required, block.timestamp)),
            sessionValidatorInitData: "mockInitData",
            erc7739Policies: erc7739Data,
            actions: new ActionData[](0),
            claimPolicies: policyDatas
        });

        Session[] memory sessions = new Session[](1);
        sessions[0] = session;
        PermissionId[] memory permissionIds =
            smartSessionEmissary.enableSessions(sessions, testLockTag);
        defaultPermissionId = permissionIds[0];
    }

    /// @notice Setup session with tokenIn whitelist check
    /// @dev Compact tokenIn config format: [count: 1][chainId: 32][id: 32] where id = lockTag |
    /// token
    function _setupSessionWithTokenInConfig(uint256 chainId, address token) internal {
        // Set active mode for policy data generation
        activeFieldMode = FIELD_TOKEN_IN;

        vm.prank(env.smartAccount1.account);

        // Create modeConfig with FIELD_TOKEN_IN enabled
        uint32 modeConfig = _createModeConfig(FIELD_TOKEN_IN, MODE_CHECK_STORAGE);

        // Pack token + lockTag into Compact ID format: [lockTag (96 high) | token (160 low)]
        bytes32 compactId = bytes32(uint256(uint96(testLockTag)) << 160 | uint256(uint160(token)));

        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({
            policy: address(compactClaimPolicy),
            initData: abi.encodePacked(
                modeConfig, // 4 bytes  - mode configuration
                uint8(1), // 1 byte   - count of entries
                chainId, // 32 bytes - chainId
                compactId // 32 bytes - packed token+lockTag
            )
        });

        ERC7739Data memory erc7739Data;

        Session memory session = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: keccak256(abi.encodePacked("tokenInSalt", chainId, token, block.timestamp)),
            sessionValidatorInitData: "mockInitData",
            erc7739Policies: erc7739Data,
            actions: new ActionData[](0),
            claimPolicies: policyDatas
        });

        Session[] memory sessions = new Session[](1);
        sessions[0] = session;
        PermissionId[] memory permissionIds =
            smartSessionEmissary.enableSessions(sessions, testLockTag);
        defaultPermissionId = permissionIds[0];
    }

    /// @notice Setup session with arbiter whitelist check
    /// @dev Arbiter config format: [count: 1][arbiter: 20]
    function _setupSessionWithArbiterConfig(address expectedArbiter) internal {
        // Set active mode for policy data generation
        activeFieldMode = FIELD_ARBITER;

        vm.prank(env.smartAccount1.account);

        // Create modeConfig with FIELD_ARBITER enabled
        uint32 modeConfig = _createModeConfig(FIELD_ARBITER, MODE_CHECK_STORAGE);

        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({
            policy: address(compactClaimPolicy),
            initData: abi.encodePacked(
                modeConfig, // 4 bytes  - mode configuration
                uint8(1), // 1 byte   - count of arbiters
                expectedArbiter // 20 bytes - arbiter address
            )
        });

        ERC7739Data memory erc7739Data;

        Session memory session = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: keccak256(abi.encodePacked("arbiterSalt", expectedArbiter, block.timestamp)),
            sessionValidatorInitData: "mockInitData",
            erc7739Policies: erc7739Data,
            actions: new ActionData[](0),
            claimPolicies: policyDatas
        });

        Session[] memory sessions = new Session[](1);
        sessions[0] = session;
        PermissionId[] memory permissionIds =
            smartSessionEmissary.enableSessions(sessions, testLockTag);
        defaultPermissionId = permissionIds[0];
    }

    /// @notice Setup session with recipient whitelist check
    /// @dev Recipient config format: [count: 1][chainId: 32][recipient: 20]
    function _setupSessionWithRecipientConfig(uint256 chainId, address recipient) internal {
        // Set active mode for policy data generation
        activeFieldMode = FIELD_RECIPIENT;

        vm.prank(env.smartAccount1.account);

        // Create modeConfig with FIELD_RECIPIENT enabled
        uint32 modeConfig = _createModeConfig(FIELD_RECIPIENT, MODE_CHECK_STORAGE);

        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({
            policy: address(compactClaimPolicy),
            initData: abi.encodePacked(
                modeConfig, // 4 bytes  - mode configuration
                uint8(1), // 1 byte   - count of entries
                chainId, // 32 bytes - chainId
                recipient // 20 bytes - recipient address
            )
        });

        ERC7739Data memory erc7739Data;

        Session memory session = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: keccak256(abi.encodePacked("recipientSalt", chainId, recipient, block.timestamp)),
            sessionValidatorInitData: "mockInitData",
            erc7739Policies: erc7739Data,
            actions: new ActionData[](0),
            claimPolicies: policyDatas
        });

        Session[] memory sessions = new Session[](1);
        sessions[0] = session;
        PermissionId[] memory permissionIds =
            smartSessionEmissary.enableSessions(sessions, testLockTag);
        defaultPermissionId = permissionIds[0];
    }

    /// @notice Setup session with tokenOut whitelist check
    /// @dev TokenOut config format: [count: 1][chainId: 32][token: 20]
    function _setupSessionWithTokenOutConfig(uint256 chainId, address token) internal {
        // Set active mode for policy data generation
        activeFieldMode = FIELD_TOKEN_OUT;

        vm.prank(env.smartAccount1.account);

        // Create modeConfig with FIELD_TOKEN_OUT enabled
        uint32 modeConfig = _createModeConfig(FIELD_TOKEN_OUT, MODE_CHECK_STORAGE);

        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({
            policy: address(compactClaimPolicy),
            initData: abi.encodePacked(
                modeConfig, // 4 bytes  - mode configuration
                uint8(1), // 1 byte   - count of entries
                chainId, // 32 bytes - chainId
                token // 20 bytes - token address
            )
        });

        ERC7739Data memory erc7739Data;

        Session memory session = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: keccak256(abi.encodePacked("tokenOutSalt", chainId, token, block.timestamp)),
            sessionValidatorInitData: "mockInitData",
            erc7739Policies: erc7739Data,
            actions: new ActionData[](0),
            claimPolicies: policyDatas
        });

        Session[] memory sessions = new Session[](1);
        sessions[0] = session;
        PermissionId[] memory permissionIds =
            smartSessionEmissary.enableSessions(sessions, testLockTag);
        defaultPermissionId = permissionIds[0];
    }

    /// @notice Setup session with recipientIsSponsor check (no chainId needed)
    /// @dev recipientIsSponsor has no init data - just the mode flag
    function _setupSessionWithRecipientIsSponsorConfig() internal {
        // Set active mode for policy data generation
        activeFieldMode = FIELD_RECIPIENT_IS_SPONSOR;

        vm.prank(env.smartAccount1.account);

        // Create modeConfig with FIELD_RECIPIENT_IS_SPONSOR enabled
        uint32 modeConfig = _createModeConfig(FIELD_RECIPIENT_IS_SPONSOR, MODE_CHECK_STORAGE);

        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({
            policy: address(compactClaimPolicy),
            initData: abi.encodePacked(modeConfig) // No additional init data needed
        });

        ERC7739Data memory erc7739Data;

        Session memory session = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: keccak256(abi.encodePacked("recipientIsSponsorSalt", block.timestamp)),
            sessionValidatorInitData: "mockInitData",
            erc7739Policies: erc7739Data,
            actions: new ActionData[](0),
            claimPolicies: policyDatas
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
        bytes32 r = bytes32(0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef);
        bytes32 s = bytes32(0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321);
        uint8 v = 27;

        bytes memory sessionValidatorSignature = abi.encodePacked(r, s, v);

        return abi.encodePacked(
            EMISSARY_SMART_SESSION,
            defaultPermissionId,
            uint256(sessionValidatorSignature.length) + 64,
            sessionValidatorSignature,
            policyData
        );
    }

    /*//////////////////////////////////////////////////////////////
                          POLICY DATA HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Creates policy data for CompactClaimPolicy.check1271SignedAction
    /// @dev Layout must match CompactClaimPolicy._validateClaim expected format:
    ///      [0:32]     domainSeparator (bytes32)
    ///      [32:64]    nonce (uint256)
    ///      [64:96]    expires (uint256)
    ///      [96:128]   otherElements length (uint256)
    ///      [128:...]  otherElements (bytes32 each, pre-hashed)
    ///      [...]      element header: arbiter (20) + elementIndex (32)
    ///      [...]      tokenIn: commitmentsHash (32) OR [count + Lock[]]
    ///      [...]      mandate: mandateHash (32) OR parsed fields
    function _createPolicyDataForElement(uint256 elementIndex) internal returns (bytes memory) {
        // For signature verification, always use the notarized chain's domain separator
        // (the chain where the compact was originally signed)
        uint256 notarizedChainId = chains.originChain1;

        uint256 currentChain = block.chainid;
        vm.chainId(notarizedChainId);
        bytes32 domainSeparator = env.compact.DOMAIN_SEPARATOR();
        vm.chainId(currentChain);

        // Get other elements (excluding the current one)
        (, bytes32[] memory otherElements) = $intent.elementHashes.withoutIndex(elementIndex);

        // Create compact data (without domain separator - that's prepended separately)
        bytes memory compactData = _createCompactData(elementIndex, otherElements);

        // Return: domainSeparator + compactData
        return abi.encodePacked(domainSeparator, compactData);
    }

    /// @notice Creates the compact data portion (everything after domainSeparator)
    /// @dev The data format depends on which fields are in CHECK_STORAGE mode
    function _createCompactData(
        uint256 elementIndex,
        bytes32[] memory otherElements
    )
        internal
        returns (bytes memory)
    {
        Element memory element = $intent.compact.elements[elementIndex];
        Types.Order memory order = _getOrder($intent.compact, elementIndex);

        // Build the base header
        bytes memory header = abi.encodePacked(
            uint256($intent.compact.nonce),
            uint256($intent.compact.expires),
            uint256(otherElements.length),
            _encodeOtherElements(otherElements),
            element.arbiter,
            uint256(elementIndex)
        );

        // TokenIn data - depends on whether FIELD_TOKEN_IN is in CHECK_STORAGE
        bytes memory tokenInData;
        if (activeFieldMode == FIELD_TOKEN_IN) {
            // CHECK_STORAGE mode: pass expanded Lock[] array
            // Format: [count: 1 byte][Lock[]: id (32) + amount (32) each]
            tokenInData = abi.encodePacked(uint8(order.tokenIn.length));
            for (uint256 i = 0; i < order.tokenIn.length; i++) {
                tokenInData =
                    abi.encodePacked(tokenInData, order.tokenIn[i][0], order.tokenIn[i][1]);
            }
        } else {
            // SKIP mode: pass commitmentsHash
            tokenInData = abi.encodePacked(hasher.hashTokenIn(order.tokenIn));
        }

        // Mandate data - depends on which mandate fields are in CHECK_STORAGE
        bytes memory mandateData;
        if (activeFieldMode == FIELD_ORIGIN_OPS) {
            // originOps in CHECK_STORAGE: pass individual mandate field hashes
            bytes32 targetHash = _computeTargetHash(element.mandate.target);
            bytes32 originOpsHash = hasher.hashOps(element.mandate.originOps);
            bytes32 destOpsHash = hasher.hashOps(element.mandate.destOps);
            bytes32 qHash = keccak256(element.mandate.q);

            mandateData = abi.encodePacked(
                targetHash,
                uint256(element.mandate.target.targetChain),
                uint128(element.mandate.minGas),
                originOpsHash,
                destOpsHash,
                qHash
            );
        } else if (
            activeFieldMode == FIELD_RECIPIENT || activeFieldMode == FIELD_TOKEN_OUT
                || activeFieldMode == FIELD_RECIPIENT_IS_SPONSOR
        ) {
            // Target fields in CHECK_STORAGE: pass expanded target + rest of mandate
            Target memory target = element.mandate.target;
            bytes32 originOpsHash = hasher.hashOps(element.mandate.originOps);
            bytes32 destOpsHash = hasher.hashOps(element.mandate.destOps);
            bytes32 qHash = keccak256(element.mandate.q);

            if (activeFieldMode == FIELD_TOKEN_OUT) {
                // TokenOut expanded: [recipient][targetChain][fillExpiry][count][token+amount...]
                mandateData = abi.encodePacked(
                    target.recipient,
                    uint256(target.targetChain),
                    uint256(target.fillExpiry),
                    uint8(target.tokenOut.length)
                );
                for (uint256 i = 0; i < target.tokenOut.length; i++) {
                    mandateData = abi.encodePacked(
                        mandateData, target.tokenOut[i][0], target.tokenOut[i][1]
                    );
                }
            } else {
                // Recipient expanded: [recipient][targetChain][fillExpiry][tokenOutHash]
                bytes32 tokenOutHash = hasher.hashTokenOut(target.tokenOut);
                mandateData = abi.encodePacked(
                    target.recipient,
                    uint256(target.targetChain),
                    uint256(target.fillExpiry),
                    tokenOutHash
                );
            }

            // Append rest of mandate
            mandateData = abi.encodePacked(
                mandateData, uint128(element.mandate.minGas), originOpsHash, destOpsHash, qHash
            );
        } else {
            // All mandate fields in SKIP mode: pass pre-computed mandateHash
            mandateData = abi.encodePacked(_computeMandateHash(element));
        }

        return abi.encodePacked(header, tokenInData, mandateData);
    }

    /// @notice Computes mandate hash from element using EIP712TypeHashLib
    function _computeMandateHash(Element memory element) internal view returns (bytes32) {
        // Compute target hash
        bytes32 targetHash = _computeTargetHash(element.mandate.target);

        // Compute ops hashes
        bytes32 originOpsHash = hasher.hashOps(element.mandate.originOps);
        bytes32 destOpsHash = hasher.hashOps(element.mandate.destOps);

        // Compute qualification hash
        bytes32 qualificationHash = keccak256(element.mandate.q);

        // Use EIP712TypeHashLib for proper hashing
        return EIP712TypeHashLib.hashMandateRaw(
            targetHash,
            uint128(element.mandate.minGas),
            originOpsHash,
            destOpsHash,
            qualificationHash
        );
    }

    /// @notice Computes target hash from target struct using EIP712TypeHashLib
    function _computeTargetHash(Target memory target) internal view returns (bytes32) {
        bytes32 tokenOutHash = hasher.hashTokenOut(target.tokenOut);

        return EIP712TypeHashLib.hashTargetAttributesRaw(
            target.recipient, tokenOutHash, target.targetChain, target.fillExpiry
        );
    }

    /// @notice Encodes other elements array as raw bytes
    function _encodeOtherElements(bytes32[] memory elements) internal pure returns (bytes memory) {
        bytes memory result;
        for (uint256 i = 0; i < elements.length; i++) {
            result = abi.encodePacked(result, elements[i]);
        }
        return result;
    }
}
