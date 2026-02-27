// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

// Dependencies
import {
    ActionPolicy_Integration_Test
} from "@test/integration/policies/ActionPolicyBase.integration.t.sol";

// Contracts
import { IntentExecutionPolicy, TargetConfig } from "@policies/execution/IntentExecutionPolicy.sol";

// Interfaces
import { IERC20 } from "@openzeppelin/contracts/interfaces/IERC20.sol";

// Libraries
import { SmartExecutionLib, Execution } from "@compact-utils/common/SmartExecutionLib.sol";

// Types
import { AccountInstance } from "@modulekit/ModuleKit.sol";
import { PermissionId, PolicyData, ActionData } from "@smartsessions/DataTypes.sol";
import { FALLBACK_TARGET_FLAG, FALLBACK_TARGET_SELECTOR_FLAG } from "@smartsessions/DataTypes.sol";
import { Vm } from "forge-std/Vm.sol";

/// @title IntentExecutionPolicy Integration Test
/// @notice Test suite for IntentExecutionPolicy using ActionPolicy_Integration_Test base
contract IntentExecutionPolicy_Integration_Test is ActionPolicy_Integration_Test {
    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    IntentExecutionPolicy intentPolicy;
    AccountInstance account;

    Vm.Wallet alice;
    Vm.Wallet bob;

    address owner;

    address whitelistedTarget;
    address nonWhitelistedTarget;
    address whitelistedSpender;

    bytes4 transferSelector;
    bytes4 approveSelector;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public override {
        super.setUp();

        // Setup owner
        owner = makeAddr("policyOwner");

        // Setup whitelisted addresses
        whitelistedTarget = makeAddr("whitelistedTarget");
        whitelistedSpender = makeAddr("whitelistedSpender");
        nonWhitelistedTarget = makeAddr("nonWhitelistedTarget");

        // Deploy policy
        intentPolicy = new IntentExecutionPolicy(owner);

        // Whitelist initial targets
        TargetConfig[] memory entries = new TargetConfig[](2);
        entries[0] = TargetConfig({ target: whitelistedTarget, allowed: true });
        entries[1] = TargetConfig({ target: whitelistedSpender, allowed: true });
        vm.prank(owner);
        intentPolicy.setWhitelistedTargets(entries);

        // Setup account
        account = makeAccountInstance("TestAccount");
        setupAccountWithEmissary(account);

        // Create test wallets
        alice = vm.createWallet("alice");
        bob = vm.createWallet("bob");

        // Setup selectors
        transferSelector = bytes4(keccak256("transfer(address,uint256)"));
        approveSelector = IERC20.approve.selector;
    }

    /*//////////////////////////////////////////////////////////////
                    SINGLE EXECUTION - TARGET WHITELIST
    //////////////////////////////////////////////////////////////*/

    function test_verifyExecution_whitelistedTarget() public {
        // Setup: enable session for transfer on whitelisted target
        bytes memory initData = "";
        PermissionId pid = enableActionSession(
            account, address(intentPolicy), initData, alice.addr, whitelistedTarget, transferSelector
        );

        // Create test digest and calldata
        bytes memory callData =
            abi.encodeWithSelector(transferSelector, address(0xBEEF), uint256(100));
        bytes32 digest =
            createTestDigest(account.account, whitelistedTarget, 0, callData, 1);

        // Validate
        bool valid = validateExecutionWithKey(
            account, pid, digest, whitelistedTarget, 0, callData, alice.privateKey
        );

        assertTrue(valid, "Whitelisted target should pass");
    }

    function test_verifyExecution_nonWhitelistedTarget() public {
        // Setup: enable session for transfer on non-whitelisted target
        bytes memory initData = "";
        PermissionId pid = enableActionSession(
            account,
            address(intentPolicy),
            initData,
            alice.addr,
            nonWhitelistedTarget,
            transferSelector
        );

        // Create test digest and calldata
        bytes memory callData =
            abi.encodeWithSelector(transferSelector, address(0xBEEF), uint256(100));
        bytes32 digest =
            createTestDigest(account.account, nonWhitelistedTarget, 0, callData, 1);

        // Validate
        bool valid = validateExecutionWithKey(
            account, pid, digest, nonWhitelistedTarget, 0, callData, alice.privateKey
        );

        assertFalse(valid, "Non-whitelisted target should fail");
    }

    /*//////////////////////////////////////////////////////////////
                    SINGLE EXECUTION - APPROVE SPENDER
    //////////////////////////////////////////////////////////////*/

    function test_verifyExecution_approve_whitelistedSpender() public {
        // Setup: enable session for approve on whitelisted target
        bytes memory initData = "";
        PermissionId pid = enableActionSession(
            account, address(intentPolicy), initData, alice.addr, whitelistedTarget, approveSelector
        );

        // Create approve calldata with whitelisted address as spender
        bytes memory callData =
            abi.encodeWithSelector(approveSelector, whitelistedSpender, uint256(1000));
        bytes32 digest =
            createTestDigest(account.account, whitelistedTarget, 0, callData, 1);

        // Validate
        bool valid = validateExecutionWithKey(
            account, pid, digest, whitelistedTarget, 0, callData, alice.privateKey
        );

        assertTrue(valid, "Approve with whitelisted spender should pass");
    }

    function test_verifyExecution_approve_nonWhitelistedSpender() public {
        // Setup: enable session for approve on non-whitelisted target
        // (whitelisted targets pass immediately, so use non-whitelisted to test spender logic)
        bytes memory initData = "";
        PermissionId pid = enableActionSession(
            account,
            address(intentPolicy),
            initData,
            alice.addr,
            nonWhitelistedTarget,
            approveSelector
        );

        // Create approve calldata with random (non-whitelisted) spender
        address randomSpender = makeAddr("randomSpender");
        bytes memory callData =
            abi.encodeWithSelector(approveSelector, randomSpender, uint256(1000));
        bytes32 digest =
            createTestDigest(account.account, nonWhitelistedTarget, 0, callData, 1);

        // Validate
        bool valid = validateExecutionWithKey(
            account, pid, digest, nonWhitelistedTarget, 0, callData, alice.privateKey
        );

        assertFalse(valid, "Approve with non-whitelisted spender should fail");
    }

    /*//////////////////////////////////////////////////////////////
                         WRONG SIGNER
    //////////////////////////////////////////////////////////////*/

    function test_verifyExecution_failsWhen_wrongSigner() public {
        // Setup: enable session for alice
        bytes memory initData = "";
        PermissionId pid = enableActionSession(
            account, address(intentPolicy), initData, alice.addr, whitelistedTarget, transferSelector
        );

        bytes memory callData =
            abi.encodeWithSelector(transferSelector, address(0xBEEF), uint256(100));
        bytes32 digest =
            createTestDigest(account.account, whitelistedTarget, 0, callData, 1);

        // Try to validate with bob's key
        bool valid = validateExecutionWithKey(
            account, pid, digest, whitelistedTarget, 0, callData, bob.privateKey
        );

        assertFalse(valid, "Should fail with wrong signer");
    }

    /*//////////////////////////////////////////////////////////////
                       BATCH EXECUTION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_verifyExecution_batch_allWhitelisted() public {
        // Setup two actions on whitelisted targets
        ActionData[] memory actions = new ActionData[](2);

        PolicyData[] memory policies1 = new PolicyData[](1);
        policies1[0] = PolicyData({ policy: address(intentPolicy), initData: "" });
        actions[0] = ActionData({
            actionTarget: whitelistedTarget,
            actionTargetSelector: transferSelector,
            actionPolicies: policies1
        });

        PolicyData[] memory policies2 = new PolicyData[](1);
        policies2[0] = PolicyData({ policy: address(intentPolicy), initData: "" });
        actions[1] = ActionData({
            actionTarget: whitelistedSpender,
            actionTargetSelector: transferSelector,
            actionPolicies: policies2
        });

        PermissionId pid = enableActionSessionMultipleActions(account, actions, alice.addr);

        // Create batch execution
        Execution[] memory executions = new Execution[](2);
        executions[0] = Execution({
            target: whitelistedTarget,
            value: 0,
            callData: abi.encodeWithSelector(transferSelector, address(0xBEEF), 100)
        });
        executions[1] = Execution({
            target: whitelistedSpender,
            value: 0,
            callData: abi.encodeWithSelector(transferSelector, address(0xCAFE), 200)
        });

        bytes32 digest = createBatchTestDigest(account.account, executions, 1);

        bool valid =
            validateBatchExecutionWithKey(account, pid, digest, executions, alice.privateKey);

        assertTrue(valid, "Batch with all whitelisted targets should pass");
    }

    function test_verifyExecution_batch_oneNonWhitelisted() public {
        // Setup: one whitelisted, one non-whitelisted target
        ActionData[] memory actions = new ActionData[](2);

        PolicyData[] memory policies1 = new PolicyData[](1);
        policies1[0] = PolicyData({ policy: address(intentPolicy), initData: "" });
        actions[0] = ActionData({
            actionTarget: whitelistedTarget,
            actionTargetSelector: transferSelector,
            actionPolicies: policies1
        });

        PolicyData[] memory policies2 = new PolicyData[](1);
        policies2[0] = PolicyData({ policy: address(intentPolicy), initData: "" });
        actions[1] = ActionData({
            actionTarget: nonWhitelistedTarget,
            actionTargetSelector: transferSelector,
            actionPolicies: policies2
        });

        PermissionId pid = enableActionSessionMultipleActions(account, actions, alice.addr);

        // Create batch execution
        Execution[] memory executions = new Execution[](2);
        executions[0] = Execution({
            target: whitelistedTarget,
            value: 0,
            callData: abi.encodeWithSelector(transferSelector, address(0xBEEF), 100)
        });
        executions[1] = Execution({
            target: nonWhitelistedTarget,
            value: 0,
            callData: abi.encodeWithSelector(transferSelector, address(0xCAFE), 200)
        });

        bytes32 digest = createBatchTestDigest(account.account, executions, 1);

        bool valid =
            validateBatchExecutionWithKey(account, pid, digest, executions, alice.privateKey);

        assertFalse(valid, "Batch should fail when any target is non-whitelisted");
    }

    /*//////////////////////////////////////////////////////////////
                     DYNAMIC WHITELIST UPDATE
    //////////////////////////////////////////////////////////////*/

    function test_verifyExecution_afterWhitelistUpdate() public {
        // Setup: enable session for transfer on initially non-whitelisted target
        address dynamicTarget = makeAddr("dynamicTarget");
        bytes memory initData = "";
        PermissionId pid = enableActionSession(
            account, address(intentPolicy), initData, alice.addr, dynamicTarget, transferSelector
        );

        bytes memory callData =
            abi.encodeWithSelector(transferSelector, address(0xBEEF), uint256(100));
        bytes32 digest = createTestDigest(account.account, dynamicTarget, 0, callData, 1);

        // First: should fail (not whitelisted)
        bool valid1 = validateExecutionWithKey(
            account, pid, digest, dynamicTarget, 0, callData, alice.privateKey
        );
        assertFalse(valid1, "Should fail before whitelisting");

        // Whitelist the target
        vm.prank(owner);
        TargetConfig[] memory entries = new TargetConfig[](1);
        entries[0] = TargetConfig({ target: dynamicTarget, allowed: true });
        intentPolicy.setWhitelistedTargets(entries);

        // Second: should pass (now whitelisted)
        bytes32 digest2 = createTestDigest(account.account, dynamicTarget, 0, callData, 2);
        bool valid2 = validateExecutionWithKey(
            account, pid, digest2, dynamicTarget, 0, callData, alice.privateKey
        );
        assertTrue(valid2, "Should pass after whitelisting");
    }
}
