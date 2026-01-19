// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import {
    SmartSessionEmissary_Unit_Test
} from "@test/unit/SmartSessionEmissary/SmartSessionEmissary.t.sol";
import { Base_Test } from "@test/Base.t.sol";

// Contracts
import {
    SmartSessionEmissaryMock as SmartSessionEmissary
} from "@mocks/SmartSessionEmissaryMock.sol";
import { MockTarget } from "@rhinestone/compact-utils/src/tests/MockTarget.sol";
import {
    ArgPolicy,
    ActionConfig,
    ParamRules,
    ParamRule,
    ParamCondition,
    LimitUsage
} from "@smartsessions/external/policies/ArgPolicy/ArgPolicy.sol";
import {
    ArgPolicyTreeLib
} from "@smartsessions/external/policies/ArgPolicy/lib/ArgPolicyTreeLib.sol";
import { Paymaster } from "@compact-utils/executor/StandaloneIntent/aux/Paymaster.sol";

// Libraries
import { TestHelperLib, CompactEnvironment } from "@compact-utils/tests/Environment.sol";
import { SmartExecutionLib } from "@rhinestone/compact-utils/src/common/SmartExecutionLib.sol";

// Interfaces
import { ISessionValidator } from "@smartsessions/interfaces/ISessionValidator.sol";
import {
    IStandaloneIntentExecutor
} from "@compact-utils/executor/interfaces/IStandaloneIntent.sol";

// Types
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
import { EMISSARY_SMART_SESSION } from "@lib/ModeLib.sol";
import { Constants } from "@compact-utils/types/Constants.sol";

/// @title StandaloneIntentExecutor + SmartSessionEmissary Integration Test
/// @notice Tests verifyExecution with batch executions including Paymaster callback
/// @dev Uses ArgPolicy to validate parameters for both MockTarget and Paymaster calls
contract SmartSessionEmissary_StandaloneExecutor_Integration_Test is
    CompactEnvironment,
    SmartSessionEmissary_Unit_Test
{
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using TestHelperLib for *;
    using SmartExecutionLib for *;
    using ArgPolicyTreeLib for *;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    ArgPolicy argPolicy;
    Paymaster paymaster;
    PermissionId defaultPermissionId;
    bytes12 testLockTag;

    // Gas refund params
    address constant GAS_TOKEN = Constants.NATIVE_TOKEN;
    uint256 constant MAX_GAS_REFUND = 0.1 ether;
    uint256 constant EXCHANGE_RATE = 1e18; // 1:1 for native token

    // MockTarget params
    uint256 constant TARGET_PARAM_VALUE = 42;
    uint256 constant TARGET_PARAM_MAX = 100; // ArgPolicy limit

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override(SmartSessionEmissary_Unit_Test) {
        // Deploy compact infrastructure (includes intentExecutor which is StandaloneIntentExecutor)
        _deployCompact();
        _deploySmartAccount({ create: true });

        // Fund the account for gas refunds
        vm.deal(env.smartAccount1.account, 10 ether);

        // Get paymaster from environment (or deploy if needed)
        paymaster = Paymaster(payable(env.paymaster));

        // Deposit ETH to paymaster for gas refunds
        vm.prank(env.smartAccount1.account);
        (bool success,) = address(paymaster).call{ value: 1 ether }("");
        require(success, "Paymaster deposit failed");

        // Deploy ArgPolicy
        argPolicy = new ArgPolicy();

        // Call Base_Test setup
        Base_Test.setUp();

        // Redeploy SmartSessionEmissary with intentExecutor
        smartSessionEmissary = new SmartSessionEmissary(address(ADDRESSBOOK));

        // Setup lockTag
        testLockTag = env.lockTag;

        // Set emissary in compact
        vm.prank(env.smartAccount1.account);
        env.compact.assignEmissary(testLockTag, address(smartSessionEmissary));
    }

    /*//////////////////////////////////////////////////////////////
                       VERIFY EXECUTION TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test batch execution with normal call + Paymaster callback using ArgPolicy
    /// @dev Both executions validated by ArgPolicy with different configs per ActionId
    function test_integration_verifyExecution_batchWithArgPolicy_succeeds() public {
        // Arrange - setup session with ArgPolicy for both actions
        _setupSessionWithArgPolicies();

        // Create batch executions
        Execution[] memory executions = new Execution[](2);

        // Execution 1: MockTarget.targetFn(42) - ArgPolicy checks param <= 100
        executions[0] = Execution({
            target: address(env.target),
            value: 0,
            callData: abi.encodeCall(MockTarget.targetFn, (TARGET_PARAM_VALUE))
        });

        // Execution 2: Paymaster.callbackAllowMaxAmount(token, maxAmount)
        // ArgPolicy checks: token == NATIVE_TOKEN && maxAmount <= MAX_GAS_REFUND
        executions[1] = Execution({
            target: address(paymaster),
            value: 0, // Don't send ETH here, already deposited
            callData: abi.encodeCall(Paymaster.callbackAllowMaxAmount, (GAS_TOKEN, MAX_GAS_REFUND))
        });

        // Build signed ops with EMISSARY_EXECUTION mode
        IStandaloneIntentExecutor.SingleChainOps memory signedOps =
            _buildSignedOps(executions, SmartExecutionLib.SigMode.EMISSARY_EXECUTION);

        // Act - execute with gas refund
        address solver = env.solver.addr;
        vm.prank(solver);
        env.intentExecutor
            .executeSinglechainOpsWithGasRefund(
                signedOps,
                IStandaloneIntentExecutor.GasRefund({
                    token: GAS_TOKEN, exchangeRate: EXCHANGE_RATE
                }),
                solver // gasRefundRecipient
            );

        // Assert
        assertEq(env.target.param(), TARGET_PARAM_VALUE, "MockTarget.targetFn should have executed");
    }

    /// @notice Test batch fails when MockTarget param exceeds ArgPolicy limit
    function test_integration_verifyExecution_batchWithArgPolicy_failsWhen_targetParamExceedsLimit()
        public
    {
        // Arrange
        _setupSessionWithArgPolicies();

        Execution[] memory executions = new Execution[](2);

        // Execution 1: MockTarget.targetFn(150) - EXCEEDS limit of 100
        executions[0] = Execution({
            target: address(env.target),
            value: 0,
            callData: abi.encodeCall(MockTarget.targetFn, (150))
        });

        executions[1] = Execution({
            target: address(paymaster),
            value: 0,
            callData: abi.encodeCall(Paymaster.callbackAllowMaxAmount, (GAS_TOKEN, MAX_GAS_REFUND))
        });

        IStandaloneIntentExecutor.SingleChainOps memory signedOps =
            _buildSignedOps(executions, SmartExecutionLib.SigMode.EMISSARY_EXECUTION);

        // Act & Assert
        address solver = env.solver.addr;
        vm.prank(solver);
        vm.expectRevert();
        env.intentExecutor
            .executeSinglechainOpsWithGasRefund(
                signedOps,
                IStandaloneIntentExecutor.GasRefund({
                    token: GAS_TOKEN, exchangeRate: EXCHANGE_RATE
                }),
                solver
            );
    }

    /// @notice Test batch fails when callback maxAmount exceeds ArgPolicy limit
    function test_integration_verifyExecution_batchWithArgPolicy_failsWhen_callbackMaxAmountExceedsLimit()
        public
    {
        // Arrange
        _setupSessionWithArgPolicies();

        Execution[] memory executions = new Execution[](2);

        executions[0] = Execution({
            target: address(env.target),
            value: 0,
            callData: abi.encodeCall(MockTarget.targetFn, (TARGET_PARAM_VALUE))
        });

        // Callback with maxAmount > allowed
        uint256 excessiveMaxAmount = 1 ether;
        executions[1] = Execution({
            target: address(paymaster),
            value: 0,
            callData: abi.encodeCall(
                Paymaster.callbackAllowMaxAmount, (GAS_TOKEN, excessiveMaxAmount)
            )
        });

        IStandaloneIntentExecutor.SingleChainOps memory signedOps =
            _buildSignedOps(executions, SmartExecutionLib.SigMode.EMISSARY_EXECUTION);

        // Act & Assert
        address solver = env.solver.addr;
        vm.prank(solver);
        vm.expectRevert();
        env.intentExecutor
            .executeSinglechainOpsWithGasRefund(
                signedOps,
                IStandaloneIntentExecutor.GasRefund({
                    token: GAS_TOKEN, exchangeRate: EXCHANGE_RATE
                }),
                solver
            );
    }

    /// @notice Test batch fails when callback uses wrong token
    function test_integration_verifyExecution_batchWithArgPolicy_failsWhen_wrongToken() public {
        // Arrange
        _setupSessionWithArgPolicies();

        address wrongToken = address(0xBAD);

        Execution[] memory executions = new Execution[](2);

        executions[0] = Execution({
            target: address(env.target),
            value: 0,
            callData: abi.encodeCall(MockTarget.targetFn, (TARGET_PARAM_VALUE))
        });

        executions[1] = Execution({
            target: address(paymaster),
            value: 0,
            callData: abi.encodeCall(Paymaster.callbackAllowMaxAmount, (wrongToken, MAX_GAS_REFUND))
        });

        IStandaloneIntentExecutor.SingleChainOps memory signedOps =
            _buildSignedOps(executions, SmartExecutionLib.SigMode.EMISSARY_EXECUTION);

        // Act & Assert
        address solver = env.solver.addr;
        vm.prank(solver);
        vm.expectRevert();
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
                         SESSION SETUP HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Setup session with ArgPolicy for both MockTarget and Paymaster actions
    function _setupSessionWithArgPolicies() internal {
        vm.prank(env.smartAccount1.account);

        // Two ActionData entries - one per (target, selector)
        ActionData[] memory actions = new ActionData[](2);

        // Action 1: MockTarget.targetFn - check param[0] <= 100
        PolicyData[] memory targetPolicies = new PolicyData[](1);
        targetPolicies[0] =
            PolicyData({ policy: address(argPolicy), initData: _createTargetFnArgPolicyConfig() });
        actions[0] = ActionData({
            actionTarget: address(env.target),
            actionTargetSelector: MockTarget.targetFn.selector,
            actionPolicies: targetPolicies
        });

        // Action 2: Paymaster.callbackAllowMaxAmount - check token == NATIVE && maxAmount <= limit
        PolicyData[] memory paymasterPolicies = new PolicyData[](1);
        paymasterPolicies[0] =
            PolicyData({ policy: address(argPolicy), initData: _createCallbackArgPolicyConfig() });
        actions[1] = ActionData({
            actionTarget: address(paymaster),
            actionTargetSelector: Paymaster.callbackAllowMaxAmount.selector,
            actionPolicies: paymasterPolicies
        });

        // Claim policies (sudo for simplicity)
        PolicyData[] memory claimPolicies = new PolicyData[](1);
        claimPolicies[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });

        ERC7739Data memory erc7739Data;

        Session memory session = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: keccak256(abi.encodePacked("argPolicyBatch", block.timestamp)),
            sessionValidatorInitData: "mockInitData",
            erc7739Policies: erc7739Data,
            actions: actions,
            claimPolicies: claimPolicies
        });

        Session[] memory sessions = new Session[](1);
        sessions[0] = session;
        PermissionId[] memory permissionIds =
            smartSessionEmissary.enableSessions(sessions, env.lockTag);
        defaultPermissionId = permissionIds[0];
    }

    /// @notice Create ArgPolicy config for MockTarget.targetFn(uint256)
    /// @dev Rule: param[0] <= TARGET_PARAM_MAX (100)
    function _createTargetFnArgPolicyConfig() internal pure returns (bytes memory) {
        ActionConfig memory config;
        config.valueLimitPerUse = 1 ether;

        // Single rule: first param <= 100
        config.paramRules.rules = new ParamRule[](1);
        config.paramRules.rules[0] = ParamRule({
            condition: ParamCondition.LESS_THAN_OR_EQUAL,
            offset: 0, // First param after selector
            isLimited: false,
            ref: bytes32(uint256(TARGET_PARAM_MAX)),
            usage: LimitUsage({ limit: 0, used: 0 })
        });

        // Single rule node
        config.paramRules.packedNodes = new uint256[](1);
        config.paramRules.packedNodes[0] = ArgPolicyTreeLib.createRuleNode(0);
        config.paramRules.rootNodeIndex = 0;

        return abi.encode(config);
    }

    /// @notice Create ArgPolicy config for Paymaster.callbackAllowMaxAmount(address token, uint256
    /// maxAmount) @dev Rules: (token == NATIVE_TOKEN) AND (maxAmount <= MAX_GAS_REFUND)
    function _createCallbackArgPolicyConfig() internal pure returns (bytes memory) {
        ActionConfig memory config;
        config.valueLimitPerUse = 1 ether;

        // Two rules combined with AND
        config.paramRules.rules = new ParamRule[](2);

        // Rule 0: token == NATIVE_TOKEN (address is at offset 0, padded to 32 bytes)
        config.paramRules.rules[0] = ParamRule({
            condition: ParamCondition.EQUAL,
            offset: 0,
            isLimited: false,
            ref: bytes32(uint256(uint160(GAS_TOKEN))),
            usage: LimitUsage({ limit: 0, used: 0 })
        });

        // Rule 1: maxAmount <= MAX_GAS_REFUND (uint256 at offset 32)
        config.paramRules.rules[1] = ParamRule({
            condition: ParamCondition.LESS_THAN_OR_EQUAL,
            offset: 32,
            isLimited: false,
            ref: bytes32(MAX_GAS_REFUND),
            usage: LimitUsage({ limit: 0, used: 0 })
        });

        // Expression tree: rule0 AND rule1
        // Node 0: Rule 0
        // Node 1: Rule 1
        // Node 2: AND(0, 1) - root
        config.paramRules.packedNodes = new uint256[](3);
        config.paramRules.packedNodes[0] = ArgPolicyTreeLib.createRuleNode(0);
        config.paramRules.packedNodes[1] = ArgPolicyTreeLib.createRuleNode(1);
        config.paramRules.packedNodes[2] = ArgPolicyTreeLib.createAndNode(0, 1);
        config.paramRules.rootNodeIndex = 2;

        return abi.encode(config);
    }

    /*//////////////////////////////////////////////////////////////
                         SIGNATURE HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Build signed SingleChainOps for the intent executor
    function _buildSignedOps(
        Execution[] memory executions,
        SmartExecutionLib.SigMode sigMode
    )
        internal
        view
        returns (IStandaloneIntentExecutor.SingleChainOps memory)
    {
        // Encode executions as operation
        Types.Operation memory ops = sigMode.encode(executions);

        // Create the SingleChainOps struct
        IStandaloneIntentExecutor.SingleChainOps memory signedOps;
        signedOps.account = env.smartAccount1.account;
        signedOps.nonce = 0; // First nonce
        signedOps.ops = ops;

        // Create SmartSession signature
        signedOps.signature = _createSmartSessionSignature(defaultPermissionId, "");

        return signedOps;
    }

    /// @notice Create SmartSession emissary signature
    function _createSmartSessionSignature(
        PermissionId permissionId,
        bytes memory policyData
    )
        internal
        pure
        returns (bytes memory)
    {
        // Mock validator signature (yesSessionValidator accepts anything)
        bytes32 r = bytes32(uint256(0x1234));
        bytes32 s = bytes32(uint256(0x5678));
        uint8 v = 27;
        bytes memory validatorSig = abi.encodePacked(r, s, v);

        return abi.encodePacked(
            SmartSessionMode.USE,
            permissionId,
            uint256(validatorSig.length) + 64, // policyDataOffset
            validatorSig,
            policyData
        );
    }
}
