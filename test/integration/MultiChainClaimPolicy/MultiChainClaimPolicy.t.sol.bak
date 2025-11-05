// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Contracts
import { SameChainAdapter } from "@compact-utils/arbiters/samechain/SameChainAdapter.sol";
import { AlwaysOKAllocator } from "@the-compact/test/AlwaysOKAllocator.sol";
import { EIP712TypeHashLib } from "@compact-utils/types/EIP712TypeHashLib.sol";
import { MultiChainClaimPolicy } from "@policies/claim/MultiChainClaimPolicy.sol";

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
import { PolicyData, ActionData, PermissionId, ConfigId } from "@smartsessions/DataTypes.sol";
import { Session } from "@types/DataTypes.sol";
import { EmissaryMode, EMISSARY_SMART_SESSION } from "@lib/ModeLib.sol";

// Test
import { SameChainBaseTest } from "@compact-utils-test/unit/SameChainArbiter/SameChain.t.sol";
import { SmartSessionEmissary_Unit_Test } from
    "@test/unit/SmartSessionEmissary/SmartSessionEmissary.t.sol";

// Temp
import { console } from "forge-std/console.sol";

/// @dev Tests MultiChainClaimPolicy integration with SmartSessionEmissary and SameChainAdapter
contract MultiChainClaimPolicy_SmartSessionEmissary_Integration_Test is
    SameChainBaseTest,
    SmartSessionEmissary_Unit_Test
{
    /*//////////////////////////////////////////////////////////////
                                 LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using ModuleKitHelpers for *;
    using TestHelperLib for *;
    using Types for Execution[];
    using HashLib for *;

    /*//////////////////////////////////////////////////////////////
                                VARIABLES
    //////////////////////////////////////////////////////////////*/

    PermissionId defaultPermissionId;
    MultiChainClaimPolicy multiChainClaimPolicy;
    Types.Order order;

    /*//////////////////////////////////////////////////////////////
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
        $intent.compact.elements.push(
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

        // Deploy MultiChainClaimPolicy
        multiChainClaimPolicy = new MultiChainClaimPolicy();

        // Setup SmartSessionEmissary with default sudo policy session
        _setupSessionWithSudoConfig();

        // Setup SmartSessionEmissary as the emissary for the account
        vm.prank(env.smartAccount1.account);
        env.compact.assignEmissary(env.lockTag, address(smartSessionEmissary));

        // Update the user emissary signature with SmartSession mode
        $intent.userEmissarySig = _createSmartSessionSignature();

        order = _getOrder($intent.compact, 0);
    }

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    // test_fillSameChain from parent will run automatically with our setup using default sudo mode

    function test_fillSameChain_withMultiChainClaimPolicy_hasExecutions() public {
        // Setup new session with hasExecutions config
        _setupSessionWithHasExecutionsConfig();

        // Create policy data for hasExecutions check
        bytes memory policyData = _createPolicyDataHaExecutions();

        // Update the signature with the new permission
        $intent.userEmissarySig = abi.encodePacked(_createSmartSessionSignature(), policyData);

        // The intent has executions (intent.targetExecutions), so it should pass
        vm.chainId(order.notarizedChainId);

        (bytes32 digest, bytes memory allocatorSig) =
            _allocatorSig(env.orchestrator, order.notarizedChainId, $intent.claimHash);

        (, bytes32[] memory otherElements) = $intent.elementHashes.withoutIndex(0);

        uint256 gas = _fill({
            chainId: order.notarizedChainId,
            solverContext: abi.encodePacked(env.solver.addr),
            adapterCalldata: abi.encodeCall(
                SameChainAdapter.samechain_compact_handleFill,
                (
                    SameChainAdapter.FillDataCompact({
                        order: order,
                        userSigs: Types.Signatures($intent.userEmissarySig, ""),
                        otherElements: otherElements,
                        allocatorData: allocatorSig,
                        preClaimGasStipend: type(uint256).max
                    })
                )
            )
        });
    }

    /*//////////////////////////////////////////////////////////////
                               HELPERS
    //////////////////////////////////////////////////////////////*/

    function _setupSessionWithSudoConfig() internal {
        // Prank to account
        vm.prank(env.smartAccount1.account);

        // Setup policies with MultiChainClaimPolicy
        // The initData should contain the actual policy configuration
        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({
            policy: address(multiChainClaimPolicy),
            initData: abi.encodePacked(uint8(0)) // Sudo mode - no conditions
         });

        // Setup session with YesSessionValidator (always validates)
        Session memory session = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: keccak256("sudoSalt"),
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

    function _setupSessionWithHasExecutionsConfig() internal {
        // Prank to account
        vm.prank(env.smartAccount1.account);

        // Setup policies with MultiChainClaimPolicy
        // The initData should contain the actual policy configuration
        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({
            policy: address(multiChainClaimPolicy),
            initData: abi.encodePacked(uint8(1)) // CHECK_HAS_EXECUTIONS
         });

        // Setup session with a different salt to create a new session
        Session memory session = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: keccak256("hasExecutionsSalt"),
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

    function _setupSessionWithTokenInConfig() internal {
        // Prank to account
        vm.prank(env.smartAccount1.account);

        // Get the expected token
        address expectedToken = address(env.token1);

        // Setup policies with MultiChainClaimPolicy
        // The initData should contain the actual policy configuration
        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({
            policy: address(multiChainClaimPolicy),
            initData: abi.encodePacked(
                uint8(8), // CHECK_TOKEN_IN
                uint256(1), // tokenInConfigs count
                chains.originChain1,
                expectedToken,
                uint128(50), // minAmount
                uint128(200) // maxAmount
            )
        });

        // Setup session with a different salt to create a new session
        Session memory session = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: keccak256("tokenInSalt"),
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

    function _createSmartSessionSignature() internal returns (bytes memory) {
        // Create mock signature components (r, s, v) for the session validator
        // In a real scenario, this would be the actual ECDSA signature of the digest
        // For testing with YesSessionValidator, it just checks that a signature exists
        bytes32 r = bytes32(0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef);
        bytes32 s = bytes32(0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321);
        uint8 v = 27;

        // Construct the session validator signature (standard ECDSA format)
        bytes memory sessionValidatorSignature = abi.encodePacked(r, s, v);

        // Format after permissionId should be:
        // [sessionValidatorSigLength (32 bytes)][sessionValidatorSignature][policyData]

        // Pack with SmartSession mode, permissionId, sig length, validator sig, then policy data
        return abi.encodePacked(
            EMISSARY_SMART_SESSION,
            defaultPermissionId,
            uint256(sessionValidatorSignature.length) + 64, // offset to policyData
            sessionValidatorSignature
        );
    }

    function _createPolicyDataHaExecutions() internal returns (bytes memory policyData) {
        // Get the domain separator from The Compact contract (not SmartSessionEmissary)
        uint256 currentChain = block.chainid;
        vm.chainId(chains.originChain1);
        bytes32 domainSeparator = env.compact.DOMAIN_SEPARATOR();
        vm.chainId(currentChain);

        // Create the compact data from the intent
        bytes memory compactData = _createCompactDataHasExecutions();

        // Create the policy data (what MultiChainClaimPolicy expects)
        policyData = abi.encodePacked(domainSeparator, compactData);
    }

    function _createCompactDataHasExecutions() internal returns (bytes memory) {
        bytes memory header = _createCompactHeader();
        bytes memory elementHeader = _createElementHeader();
        bytes memory mandateData = _createMandateData();
        bytes32 tokenInHash = hasher.hashTokenIn(order.tokenIn);
        return abi.encodePacked(header, elementHeader, tokenInHash, mandateData);
    }

    /// @notice Create mandate data for tokenIn tests
    function _createMandateData() private returns (bytes memory) {
        return abi.encodePacked(
            hasher.hashTargetAttributes(order), // targetHash
            hasher.hashOps($intent.compact.elements[0].mandate.originOps), // preClaimOpsHash
            hasher.hashOps($intent.compact.elements[0].mandate.destOps), // targetOpsHash
            keccak256($intent.compact.elements[0].mandate.q) // qualificationHash
        );
    }

    /// @notice Create the compact header (sponsor + nonce + expires + otherElements)
    function _createCompactHeader() private returns (bytes memory) {
        return abi.encodePacked(
            address($intent.compact.sponsor), // sponsor
            uint256($intent.compact.nonce), // nonce
            uint256($intent.compact.expires), // expires
            uint256($intent.elementHashes.length - 1) // otherElements count
        );
    }

    /// @notice Create the element header (arbiter + reserved + chainId)
    function _createElementHeader() private returns (bytes memory) {
        return abi.encodePacked(
            address($intent.compact.elements[0].arbiter), // arbiter
            bytes12(0), // padding
            uint256($intent.compact.elements[0].chainId) // chainId
        );
    }
}
