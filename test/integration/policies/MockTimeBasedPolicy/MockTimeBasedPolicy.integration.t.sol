// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Dependencies
import {
    Policy1271IntegrationTest
} from "@test/integration/policies/1271PolicyBase.integration.t.sol";

// Contracts
import { MockTimeBasedPolicy } from "@mocks/MockTimeBasedPolicy.sol";

// Types
import { AccountInstance } from "@modulekit/ModuleKit.sol";
import { PermissionId } from "@smartsessions/DataTypes.sol";
import { Vm } from "forge-std/Vm.sol";

/// @title MockTimeBasedPolicy Integration Test
/// @dev A mock test suite for the MockTimeBasedPolicy contract to demonstrate how to test using
///      Policy1271IntegrationTest base
contract MockTimeBasedPolicy_Integration_Test is Policy1271IntegrationTest {
    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    MockTimeBasedPolicy policy;
    AccountInstance account;

    Vm.Wallet alice;
    Vm.Wallet bob;

    bytes32 appDomain;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public override {
        super.setUp();

        // Deploy policy
        policy = new MockTimeBasedPolicy();

        // Setup account
        account = makeAccountInstance("TestAccount");
        setupAccountWithEmissary(account);

        // Create test wallets
        alice = vm.createWallet("alice");
        bob = vm.createWallet("bob");

        // Create app domain for ERC7739 tests
        appDomain = createAppDomainSeparator("TestApp", "1.0");
    }

    /*//////////////////////////////////////////////////////////////
                          DIRECT MODE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_isValidSignatureWithSender_directMode_validSignature() public {
        // Setup policy: valid from now to 1 hour, max 1000 ETH
        uint256 validAfter = block.timestamp;
        uint256 validUntil = block.timestamp + 1 hours;
        bytes memory initData = abi.encode(alice.addr, validAfter, validUntil, 1000 ether);

        // Enable direct mode session with alice as signer
        PermissionId pid = enableDirectModeSession(account, address(policy), initData, alice.addr);

        // Create any hash and valid policy data
        bytes32 hash = keccak256("Hello World");
        bytes memory policyData = abi.encode(alice.addr, 500 ether, block.timestamp + 30 minutes);

        // Test 1: Validate using alice's key explicitly
        bool valid = validateDirectModeWithKey(account, pid, hash, alice.privateKey, policyData);
        assertTrue(valid, "Direct mode validation should pass with correct signer");

        // Test 2: Use the signDirectMode helper
        bytes memory aliceSig = signDirectMode(account.account, hash, alice.privateKey);
        valid = validateDirectModeWithSignature(account, pid, hash, aliceSig, policyData);
        assertTrue(valid, "Should validate with pre-created signature");
    }

    function test_isValidSignatureWithSender_directMode_invalidSignature_wrongSigner() public {
        // Setup for alice
        bytes memory initData =
            abi.encode(alice.addr, block.timestamp, block.timestamp + 1 hours, 1000 ether);
        PermissionId pid = enableDirectModeSession(account, address(policy), initData, alice.addr);

        // Try to validate with bob's key
        bytes32 hash = keccak256("Hello World");
        bytes memory policyData = abi.encode(alice.addr, 500 ether, block.timestamp);

        bool valid = validateDirectModeWithKey(account, pid, hash, bob.privateKey, policyData);
        assertFalse(valid, "Should fail with wrong validator key");
    }

    function test_isValidSignatureWithSender_directMode_invalidSignature_wrongPolicySigner()
        public
    {
        // Policy expects alice, but policy data contains bob
        bytes memory initData =
            abi.encode(alice.addr, block.timestamp, block.timestamp + 1 hours, 1000 ether);
        PermissionId pid = enableDirectModeSession(account, address(policy), initData, alice.addr);

        bytes32 hash = keccak256("Test");
        bytes memory policyData = abi.encode(bob.addr, 500 ether, block.timestamp); // Wrong signer
        // in policy data

        bool valid = validateDirectModeWithKey(account, pid, hash, alice.privateKey, policyData);
        assertFalse(valid, "Should fail when policy data contains wrong signer");
    }

    function test_isValidSignatureWithSender_directMode_invalidSignature_outsideTimeWindow()
        public
    {
        // Valid from 1 hour to 2 hours from now
        uint256 validAfter = block.timestamp + 1 hours;
        uint256 validUntil = block.timestamp + 2 hours;
        bytes memory initData = abi.encode(alice.addr, validAfter, validUntil, 1000 ether);
        PermissionId pid = enableDirectModeSession(account, address(policy), initData, alice.addr);

        // Try to use now (too early)
        bytes32 hash = keccak256("Test");
        bytes memory policyData = abi.encode(alice.addr, 500 ether, block.timestamp); // Current
        // time is too early

        bool valid = validateDirectModeWithKey(account, pid, hash, alice.privateKey, policyData);
        assertFalse(valid, "Should fail outside time window");
    }

    function test_isValidSignatureWithSender_directMode_invalidSignature_amountTooHigh() public {
        bytes memory initData =
            abi.encode(alice.addr, block.timestamp, block.timestamp + 1 hours, 100 ether);
        PermissionId pid = enableDirectModeSession(account, address(policy), initData, alice.addr);

        bytes32 hash = keccak256("Test");
        bytes memory policyData = abi.encode(alice.addr, 200 ether, block.timestamp); // Amount too
        // high

        bool valid = validateDirectModeWithKey(account, pid, hash, alice.privateKey, policyData);
        assertFalse(valid, "Should fail when amount exceeds limit");
    }

    function test_isValidSignatureWithSender_directMode_usingDefaultWallet() public {
        // Enable session with default test wallet
        bytes memory initData =
            abi.encode(testWallet.addr, block.timestamp, block.timestamp + 1 hours, 1000 ether);
        PermissionId pid = enableDirectModeSession(account, address(policy), initData); // Uses
        // testWallet by default

        bytes32 hash = keccak256("Test");
        bytes memory policyData = abi.encode(testWallet.addr, 500 ether, block.timestamp);

        // Can use validateDirectMode without specifying key
        bool valid = validateDirectMode(account, pid, hash, policyData);
        assertTrue(valid, "Should validate with default wallet");
    }

    /*//////////////////////////////////////////////////////////////
                          ERC7739 MODE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_isValidSignatureWithSender_erc7739_permitExample() public {
        // Setup session for Permit-style signatures
        bytes memory initData =
            abi.encode(alice.addr, block.timestamp, block.timestamp + 1 hours, 1000 ether);

        string[] memory contentTypes = new string[](1);
        contentTypes[0] =
        "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)";

        string[] memory contentNames = new string[](1);
        contentNames[0] = "Permit";

        PermissionId pid = enableERC7739Session(
            account, address(policy), initData, alice.addr, appDomain, contentTypes, contentNames
        );

        // Create permit typed data
        bytes memory permitData = abi.encode(
            account.account, // owner
            address(0x1234), // spender
            1000 ether, // value
            0, // nonce
            block.timestamp + 1 hours // deadline
        );

        bytes memory policyData = abi.encode(alice.addr, 500 ether, block.timestamp);

        // Validate the typed data signature
        bool valid = validateERC7739WithKey(
            account,
            pid,
            appDomain,
            contentTypes[0],
            contentNames[0],
            permitData,
            alice.privateKey,
            policyData
        );

        assertTrue(valid, "ERC7739 permit should validate");
    }

    function test_isValidSignatureWithSender_erc7739_multipleContentTypes() public {
        bytes memory initData =
            abi.encode(alice.addr, block.timestamp, block.timestamp + 1 hours, 1000 ether);

        // Allow both Permit and Transfer types
        string[] memory contentTypes = new string[](2);
        contentTypes[0] = "Permit(address owner,address spender,uint256 value)";
        contentTypes[1] = "Transfer(address to,uint256 amount)";

        string[] memory contentNames = new string[](2);
        contentNames[0] = "Permit";
        contentNames[1] = "Transfer";

        PermissionId pid = enableERC7739Session(
            account, address(policy), initData, alice.addr, appDomain, contentTypes, contentNames
        );

        // Test Transfer type
        bytes memory transferData = abi.encode(
            address(0xBEEF), // to
            100 ether // amount
        );

        bytes memory policyData = abi.encode(alice.addr, 100 ether, block.timestamp);

        bool valid = validateERC7739WithKey(
            account,
            pid,
            appDomain,
            contentTypes[1], // Use Transfer type
            contentNames[1],
            transferData,
            alice.privateKey,
            policyData
        );

        assertTrue(valid, "Should validate Transfer type");
    }

    function test_isValidSignatureWithSender_erc7739_wrongContentType() public {
        // Enable session for Permit only
        bytes memory initData =
            abi.encode(alice.addr, block.timestamp, block.timestamp + 1 hours, 1000 ether);

        string[] memory contentTypes = new string[](1);
        contentTypes[0] = "Permit(address owner,address spender,uint256 value)";

        string[] memory contentNames = new string[](1);
        contentNames[0] = "Permit";

        PermissionId pid = enableERC7739Session(
            account, address(policy), initData, alice.addr, appDomain, contentTypes, contentNames
        );

        // Try to use Transfer type (not enabled)
        bytes memory transferData = abi.encode(address(0xBEEF), 100 ether);
        bytes memory policyData = abi.encode(alice.addr, 100 ether, block.timestamp);

        bool valid = validateERC7739WithKey(
            account,
            pid,
            appDomain,
            "Transfer(address to,uint256 amount)", // Wrong type
            "Transfer", // Wrong name
            transferData,
            alice.privateKey,
            policyData
        );

        assertFalse(valid, "Should fail with non-enabled content type");
    }

    function test_isValidSignatureWithSender_erc7739_wrongAppDomain() public {
        bytes memory initData =
            abi.encode(alice.addr, block.timestamp, block.timestamp + 1 hours, 1000 ether);

        string[] memory contentTypes = new string[](1);
        contentTypes[0] = "Test(uint256 value)";

        string[] memory contentNames = new string[](1);
        contentNames[0] = "Test";

        // Enable for appDomain
        PermissionId pid = enableERC7739Session(
            account, address(policy), initData, alice.addr, appDomain, contentTypes, contentNames
        );

        // Try to validate with different domain
        bytes32 wrongDomain = createAppDomainSeparator("WrongApp", "1.0");

        bytes memory testData = abi.encode(123);
        bytes memory policyData = abi.encode(alice.addr, 100 ether, block.timestamp);

        bool valid = validateERC7739WithKey(
            account,
            pid,
            wrongDomain, // Wrong domain
            contentTypes[0],
            contentNames[0],
            testData,
            alice.privateKey,
            policyData
        );

        assertFalse(valid, "Should fail with wrong app domain");
    }
}
