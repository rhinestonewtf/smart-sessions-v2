// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import {
    ActionPolicy_Integration_Test
} from "@test/integration/policies/ActionPolicyBase.integration.t.sol";

// Contracts
import { MockSpendingLimitPolicy } from "@mocks/MockSpendingLimitPolicy.sol";

// Libraries
import { SmartExecutionLib, Execution } from "@compact-utils/common/SmartExecutionLib.sol";

// Types
import { AccountInstance } from "@modulekit/ModuleKit.sol";
import { PermissionId, PolicyData, ActionData } from "@smartsessions/DataTypes.sol";
import { Vm } from "forge-std/Vm.sol";
import { FALLBACK_TARGET_FLAG, FALLBACK_TARGET_SELECTOR_FLAG } from "@smartsessions/DataTypes.sol";

/// @title MockSpendingLimitPolicy Integration Test
/// @notice Test suite for MockSpendingLimitPolicy using ActionPolicy_Integration_Test base
contract MockSpendingLimitPolicy_Integration_Test is ActionPolicy_Integration_Test {
    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    MockSpendingLimitPolicy policy;
    AccountInstance account;

    Vm.Wallet alice;
    Vm.Wallet bob;

    address _targetContract;
    bytes4 allowedSelector;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public override {
        super.setUp();

        // Deploy policy
        policy = new MockSpendingLimitPolicy();

        // Setup account
        account = makeAccountInstance("TestAccount");
        setupAccountWithEmissary(account);

        // Create test wallets
        alice = vm.createWallet("alice");
        bob = vm.createWallet("bob");

        // Setup target contract and selector
        _targetContract = makeAddr("_targetContract");
        allowedSelector = bytes4(keccak256("transfer(address,uint256)"));
    }

    /*//////////////////////////////////////////////////////////////
                       SINGLE EXECUTION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_verifyExecution_validExecution() public {
        // Setup policy: allow _targetContract, allowedSelector, max 1 ETH, unlimited calls
        bytes memory initData = abi.encode(_targetContract, allowedSelector, 1 ether, uint256(0));

        // Enable action session
        PermissionId pid = enableActionSession(
            account, address(policy), initData, alice.addr, _targetContract, allowedSelector
        );

        // Create test digest and calldata
        bytes32 digest = createTestDigest(
            account.account, _targetContract, 0.5 ether, abi.encodeWithSelector(allowedSelector), 1
        );

        // Validate execution
        bool valid = validateExecutionWithKey(
            account,
            pid,
            digest,
            _targetContract,
            0.5 ether,
            abi.encodeWithSelector(allowedSelector, address(0xBEEF), 100),
            alice.privateKey
        );

        assertTrue(valid, "Valid execution should pass");
    }

    function test_verifyExecution_usingDefaultWallet() public {
        bytes memory initData = abi.encode(_targetContract, allowedSelector, 1 ether, uint256(0));

        // Enable with default testWallet
        PermissionId pid = enableActionSession(
            account, address(policy), initData, _targetContract, allowedSelector
        );

        bytes32 digest = createTestDigest(
            account.account, _targetContract, 0.5 ether, abi.encodeWithSelector(allowedSelector), 1
        );

        // Use validateExecution which uses testWallet by default
        bool valid = validateExecution(
            account,
            pid,
            digest,
            _targetContract,
            0.5 ether,
            abi.encodeWithSelector(allowedSelector, address(0xBEEF), 100)
        );

        assertTrue(valid, "Should validate with default wallet");
    }

    function test_verifyExecution_failsWhen_wrongSigner() public {
        bytes memory initData = abi.encode(_targetContract, allowedSelector, 1 ether, uint256(0));

        // Enable for alice
        PermissionId pid = enableActionSession(
            account, address(policy), initData, alice.addr, _targetContract, allowedSelector
        );

        bytes32 digest = createTestDigest(
            account.account, _targetContract, 0.5 ether, abi.encodeWithSelector(allowedSelector), 1
        );

        // Try to validate with bob's key
        bool valid = validateExecutionWithKey(
            account,
            pid,
            digest,
            _targetContract,
            0.5 ether,
            abi.encodeWithSelector(allowedSelector),
            bob.privateKey
        );

        assertFalse(valid, "Should fail with wrong signer");
    }

    function test_verifyExecution_failsWhen_valueTooHigh() public {
        // Max value is 1 ETH
        bytes memory initData = abi.encode(_targetContract, allowedSelector, 1 ether, uint256(0));

        PermissionId pid = enableActionSession(
            account, address(policy), initData, alice.addr, _targetContract, allowedSelector
        );

        bytes32 digest = createTestDigest(
            account.account, _targetContract, 2 ether, abi.encodeWithSelector(allowedSelector), 1
        );

        // Try to send 2 ETH (exceeds limit)
        bool valid = validateExecutionWithKey(
            account,
            pid,
            digest,
            _targetContract,
            2 ether,
            abi.encodeWithSelector(allowedSelector),
            alice.privateKey
        );

        assertFalse(valid, "Should fail when value exceeds limit");
    }

    function test_verifyExecution_failsWhen_wrongTarget() public {
        bytes memory initData = abi.encode(_targetContract, allowedSelector, 1 ether, uint256(0));

        PermissionId pid = enableActionSession(
            account, address(policy), initData, alice.addr, _targetContract, allowedSelector
        );

        address wrongTarget = makeAddr("wrongTarget");
        bytes32 digest = createTestDigest(
            account.account, wrongTarget, 0.5 ether, abi.encodeWithSelector(allowedSelector), 1
        );

        // Try to call wrong target
        bool valid = validateExecutionWithKey(
            account,
            pid,
            digest,
            wrongTarget,
            0.5 ether,
            abi.encodeWithSelector(allowedSelector),
            alice.privateKey
        );

        assertFalse(valid, "Should fail with wrong target");
    }

    function test_verifyExecution_failsWhen_wrongSelector() public {
        bytes memory initData = abi.encode(_targetContract, allowedSelector, 1 ether, uint256(0));

        PermissionId pid = enableActionSession(
            account, address(policy), initData, alice.addr, _targetContract, allowedSelector
        );

        bytes4 wrongSelector = bytes4(keccak256("approve(address,uint256)"));
        bytes32 digest = createTestDigest(
            account.account, _targetContract, 0.5 ether, abi.encodeWithSelector(wrongSelector), 1
        );

        // Try to call wrong selector
        bool valid = validateExecutionWithKey(
            account,
            pid,
            digest,
            _targetContract,
            0.5 ether,
            abi.encodeWithSelector(wrongSelector),
            alice.privateKey
        );

        assertFalse(valid, "Should fail with wrong selector");
    }

    /*//////////////////////////////////////////////////////////////
                       BATCH EXECUTION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_verifyExecution_batchExecution_allValid() public {
        // Setup two actions
        bytes4 selector1 = bytes4(keccak256("transfer(address,uint256)"));
        bytes4 selector2 = bytes4(keccak256("approve(address,uint256)"));
        address target1 = makeAddr("target1");
        address target2 = makeAddr("target2");

        // Create action data for both
        ActionData[] memory actions = new ActionData[](2);

        PolicyData[] memory policies1 = new PolicyData[](1);
        policies1[0] = PolicyData({
            policy: address(policy), initData: abi.encode(target1, selector1, 1 ether, uint256(0))
        });
        actions[0] = ActionData({
            actionTarget: target1, actionTargetSelector: selector1, actionPolicies: policies1
        });

        PolicyData[] memory policies2 = new PolicyData[](1);
        policies2[0] = PolicyData({
            policy: address(policy), initData: abi.encode(target2, selector2, 1 ether, uint256(0))
        });
        actions[1] = ActionData({
            actionTarget: target2, actionTargetSelector: selector2, actionPolicies: policies2
        });

        PermissionId pid = enableActionSessionMultipleActions(account, actions, alice.addr);

        // Create batch execution
        Execution[] memory executions = new Execution[](2);
        executions[0] = Execution({
            target: target1,
            value: 0.5 ether,
            callData: abi.encodeWithSelector(selector1, address(0xBEEF), 100)
        });
        executions[1] = Execution({
            target: target2,
            value: 0.3 ether,
            callData: abi.encodeWithSelector(selector2, address(0xCAFE), 200)
        });

        bytes32 digest = createBatchTestDigest(account.account, executions, 1);

        bool valid =
            validateBatchExecutionWithKey(account, pid, digest, executions, alice.privateKey);

        assertTrue(valid, "Batch execution should pass when all actions are valid");
    }

    function test_verifyExecution_batchExecution_failsWhen_oneInvalid() public {
        // Setup two actions
        bytes4 selector1 = bytes4(keccak256("transfer(address,uint256)"));
        bytes4 selector2 = bytes4(keccak256("approve(address,uint256)"));
        address target1 = makeAddr("target1");
        address target2 = makeAddr("target2");

        ActionData[] memory actions = new ActionData[](2);

        PolicyData[] memory policies1 = new PolicyData[](1);
        policies1[0] = PolicyData({
            policy: address(policy), initData: abi.encode(target1, selector1, 1 ether, uint256(0))
        });
        actions[0] = ActionData({
            actionTarget: target1, actionTargetSelector: selector1, actionPolicies: policies1
        });

        PolicyData[] memory policies2 = new PolicyData[](1);
        policies2[0] = PolicyData({
            policy: address(policy),
            initData: abi.encode(target2, selector2, 0.1 ether, uint256(0)) // Low limit!
        });
        actions[1] = ActionData({
            actionTarget: target2, actionTargetSelector: selector2, actionPolicies: policies2
        });

        PermissionId pid = enableActionSessionMultipleActions(account, actions, alice.addr);

        // Create batch where second execution exceeds limit
        Execution[] memory executions = new Execution[](2);
        executions[0] = Execution({
            target: target1,
            value: 0.5 ether,
            callData: abi.encodeWithSelector(selector1, address(0xBEEF), 100)
        });
        executions[1] = Execution({
            target: target2,
            value: 0.5 ether, // Exceeds 0.1 ETH limit!
            callData: abi.encodeWithSelector(selector2, address(0xCAFE), 200)
        });

        bytes32 digest = createBatchTestDigest(account.account, executions, 1);

        bool valid =
            validateBatchExecutionWithKey(account, pid, digest, executions, alice.privateKey);

        assertFalse(valid, "Batch should fail when any action is invalid");
    }

    /*//////////////////////////////////////////////////////////////
                       CALL COUNT LIMIT TESTS
    //////////////////////////////////////////////////////////////*/

    function test_verifyExecution_callCountLimit() public {
        // Allow max 2 calls
        bytes memory initData = abi.encode(_targetContract, allowedSelector, 1 ether, uint256(2));

        PermissionId pid = enableActionSession(
            account, address(policy), initData, alice.addr, _targetContract, allowedSelector
        );

        // First call - should succeed
        bytes32 digest1 = createTestDigest(
            account.account, _targetContract, 0.1 ether, abi.encodeWithSelector(allowedSelector), 1
        );
        bool valid1 = validateExecutionWithKey(
            account,
            pid,
            digest1,
            _targetContract,
            0.1 ether,
            abi.encodeWithSelector(allowedSelector),
            alice.privateKey
        );
        assertTrue(valid1, "First call should succeed");

        // Second call - should succeed
        bytes32 digest2 = createTestDigest(
            account.account, _targetContract, 0.1 ether, abi.encodeWithSelector(allowedSelector), 2
        );
        bool valid2 = validateExecutionWithKey(
            account,
            pid,
            digest2,
            _targetContract,
            0.1 ether,
            abi.encodeWithSelector(allowedSelector),
            alice.privateKey
        );
        assertTrue(valid2, "Second call should succeed");

        // Third call - should fail (exceeded limit)
        bytes32 digest3 = createTestDigest(
            account.account, _targetContract, 0.1 ether, abi.encodeWithSelector(allowedSelector), 3
        );
        bool valid3 = validateExecutionWithKey(
            account,
            pid,
            digest3,
            _targetContract,
            0.1 ether,
            abi.encodeWithSelector(allowedSelector),
            alice.privateKey
        );
        assertFalse(valid3, "Third call should fail - exceeded call limit");
    }

    /*//////////////////////////////////////////////////////////////
                           FALLBACK/WILDCARD TESTS
    //////////////////////////////////////////////////////////////*/

    function test_verifyExecution_fallbackPolicy_anyTargetSelector() public {
        // Setup fallback policy that applies to any target/selector
        bytes memory initData = abi.encode(
            FALLBACK_TARGET_FLAG, // Use fallback flag as the "target" key
            FALLBACK_TARGET_SELECTOR_FLAG, // Use fallback selector flag
            1 ether,
            uint256(0)
        );

        // Enable session with FALLBACK_TARGET_FLAG
        PolicyData[] memory policies = new PolicyData[](1);
        policies[0] = PolicyData({ policy: address(policy), initData: initData });

        ActionData[] memory actions = new ActionData[](1);
        actions[0] = ActionData({
            actionTarget: FALLBACK_TARGET_FLAG, // address(1)
            actionTargetSelector: FALLBACK_TARGET_SELECTOR_FLAG, // 0x00000001
            actionPolicies: policies
        });

        PermissionId pid = enableActionSessionMultipleActions(account, actions, alice.addr);

        // Now execute against ANY random target/selector - fallback policy applies
        address randomTarget = makeAddr("randomTarget");
        bytes4 randomSelector = bytes4(keccak256("randomFunction()"));

        bytes32 digest = createTestDigest(
            account.account, randomTarget, 0.5 ether, abi.encodeWithSelector(randomSelector), 1
        );

        bool valid = validateExecutionWithKey(
            account,
            pid,
            digest,
            randomTarget,
            0.5 ether,
            abi.encodeWithSelector(randomSelector),
            alice.privateKey
        );

        assertTrue(valid, "Fallback policy should allow any target/selector");
    }

    /*//////////////////////////////////////////////////////////////
                       ISOLATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_verifyExecution_isolatedPerPermissionId() public {
        bytes memory initData = abi.encode(_targetContract, allowedSelector, 1 ether, uint256(0));

        // Create two different sessions
        PermissionId pid1 = enableActionSession(
            account, address(policy), initData, alice.addr, _targetContract, allowedSelector
        );

        // Warp time to get different salt
        vm.warp(block.timestamp + 1);

        bytes4 otherSelector = bytes4(keccak256("otherFunction()"));
        bytes memory initData2 = abi.encode(_targetContract, otherSelector, 1 ether, uint256(0));
        PermissionId pid2 = enableActionSession(
            account, address(policy), initData2, alice.addr, _targetContract, otherSelector
        );

        // Try to use pid2 with allowedSelector (should fail)
        bytes32 digest = createTestDigest(
            account.account, _targetContract, 0.5 ether, abi.encodeWithSelector(allowedSelector), 1
        );

        bool valid = validateExecutionWithKey(
            account,
            pid2, // Wrong permission ID for this selector
            digest,
            _targetContract,
            0.5 ether,
            abi.encodeWithSelector(allowedSelector),
            alice.privateKey
        );

        assertFalse(valid, "Should fail when using wrong permissionId");
    }

    function test_verifyExecution_isolatedPerAccount() public {
        bytes memory initData = abi.encode(_targetContract, allowedSelector, 1 ether, uint256(0));

        PermissionId pid = enableActionSession(
            account, address(policy), initData, alice.addr, _targetContract, allowedSelector
        );

        // Create different account
        AccountInstance memory account2 = makeAccountInstance("TestAccount2");
        setupAccountWithEmissary(account2);

        bytes32 digest = createTestDigest(
            account2.account, _targetContract, 0.5 ether, abi.encodeWithSelector(allowedSelector), 1
        );

        // Try to use session from account1 on account2
        bool valid = validateExecutionWithKey(
            account2, // Different account!
            pid,
            digest,
            _targetContract,
            0.5 ether,
            abi.encodeWithSelector(allowedSelector),
            alice.privateKey
        );

        assertFalse(valid, "Should fail when using session on different account");
    }
}
