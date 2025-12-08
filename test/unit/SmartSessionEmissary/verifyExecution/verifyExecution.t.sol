// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import {
    SmartSessionEmissary_Unit_Test
} from "@test/unit/SmartSessionEmissary/SmartSessionEmissary.t.sol";

// Interfaces
import { ISmartSessionEmissary } from "@interfaces/ISmartSessionEmissary.sol";
import { ISessionValidator } from "@smartsessions/interfaces/ISessionValidator.sol";
import { IERC7579Account } from "erc7579/interfaces/IERC7579Account.sol";
import { IStatelessValidator } from "@compact-utils/interfaces/IStatelessValidator.sol";
import { ISmartSessionLens } from "@interfaces/ISmartSessionLens.sol";

// Libraries
import { ExecutionLib } from "@smartsessions/lib/ExecutionLib.sol";
import { HashLib } from "@smartsessions/lib/HashLib.sol";
import { ModuleKitHelpers } from "@modulekit/ModuleKit.sol";
import { LibZip } from "solady/utils/LibZip.sol";
import { WebAuthn } from "@webauthn/WebAuthn.sol";
import { SmartExecutionLib, Execution } from "@compact-utils/common/SmartExecutionLib.sol";

// Types
import {
    PolicyData,
    ActionData,
    FALLBACK_TARGET_FLAG,
    FALLBACK_TARGET_SELECTOR_FLAG,
    PermissionId,
    ActionId,
    EnableSession,
    ERC7739Data
} from "@smartsessions/DataTypes.sol";
import {
    ExecType,
    CallType,
    CALLTYPE_BATCH,
    CALLTYPE_SINGLE,
    EXECTYPE_DEFAULT,
    EXECTYPE_TRY,
    CALLTYPE_DELEGATECALL,
    ModeCode,
    ModeLib,
    ModePayload,
    MODE_DEFAULT
} from "erc7579/lib/ModeLib.sol";
import { EmissaryMode, EMISSARY_SMART_SESSION } from "@lib/ModeLib.sol";
import { MODULE_TYPE_VALIDATOR } from "erc7579/interfaces/IERC7579Module.sol";
import { Session } from "@types/DataTypes.sol";
import { Types } from "@rhinestone/compact-utils/src/types/OrderTypes.sol";

contract SmartSessionEmissary_verifyExecution_Test is SmartSessionEmissary_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using ModuleKitHelpers for *;
    using LibZip for bytes;
    using HashLib for *;
    using SmartExecutionLib for *;

    /*//////////////////////////////////////////////////////////////
                                 VARIABLES
    //////////////////////////////////////////////////////////////*/

    PermissionId testPermissionId;
    bytes mockSignature;
    Types.Operation mockExecData;
    bytes32 TEST_HASH;
    bytes4 mockTargetSelector;
    address testValidator;
    bytes12 testLockTag = bytes12(keccak256("mockLockTag"));

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        // Call the base setup function.
        super.setUp();

        // Init variables
        mockSignature = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        TEST_HASH = keccak256("testHash");

        // Setup mock execution data for a single call
        mockTargetSelector = bytes4(keccak256("testFunction()"));
        bytes memory callData = abi.encodeWithSelector(mockTargetSelector);
        Execution[] memory executions = new Execution[](1);
        executions[0] = Execution({ target: target, value: value, callData: callData });
        mockExecData = SmartExecutionLib.SigMode.EMISSARY.encode(executions);

        // Setup testValidator as default validator
        testValidator = address(instance.defaultValidator);

        // Deploy the account instance
        instance.deployAccount();
    }

    /*//////////////////////////////////////////////////////////////
                             SMART SESSION
    //////////////////////////////////////////////////////////////*/

    function test_verifyExecution_SmartSession_Success() public withEnabledSudoSession {
        // Arrange
        bytes memory data = packData(EMISSARY_SMART_SESSION, testPermissionId, mockSignature);

        // Prank to intent executor
        vm.prank(MOCK_INTENT_EXECUTOR);

        // Act
        bytes4 result = smartSessionEmissary.verifyExecution(
            instance.account, TEST_HASH, data, mockExecData, testLockTag
        );

        // Assert
        assertEq(
            result,
            ISmartSessionEmissary.verifyExecution.selector,
            "Should return successful verification selector"
        );
    }

    function test_verifyExecution_SmartSession_RevertsWhen_InvalidPermissionId() public {
        // Arrange
        PermissionId invalidPermissionId = PermissionId.wrap(keccak256("invalid"));
        bytes memory data = packData(EMISSARY_SMART_SESSION, invalidPermissionId, mockSignature);

        // Prank to intent executor
        vm.prank(MOCK_INTENT_EXECUTOR);

        // Act/Assert
        vm.expectRevert(
            abi.encodeWithSelector(
                ISmartSessionEmissary.InvalidPermissionId.selector, invalidPermissionId
            )
        );
        smartSessionEmissary.verifyExecution(
            instance.account, TEST_HASH, data, mockExecData, testLockTag
        );
    }

    function test_verifyExecution_SmartSession_BatchCall_Success()
        public
        withEnabledBatchSudoSession
    {
        // Arrange
        bytes memory data = packData(EMISSARY_SMART_SESSION, testPermissionId, mockSignature);

        // Create mock batch execution data
        Execution[] memory executions = new Execution[](2);

        executions[0] = Execution({
            target: target, value: value, callData: abi.encodeWithSelector(mockTargetSelector)
        });

        executions[1] = Execution({
            target: address(0x123),
            value: 0,
            callData: abi.encodeWithSelector(bytes4(keccak256("anotherFunction()")))
        });

        // Prank to intent executor
        vm.prank(MOCK_INTENT_EXECUTOR);

        // Act
        bytes4 result = smartSessionEmissary.verifyExecution(
            instance.account,
            TEST_HASH,
            data,
            SmartExecutionLib.SigMode.EMISSARY.encode(executions),
            testLockTag
        );

        // Assert
        assertEq(
            result,
            ISmartSessionEmissary.verifyExecution.selector,
            "Should return successful verification selector for batch execution"
        );
    }

    function test_verifyExecution_SmartSession_InvalidSignature()
        public
        withEnabledSessionWithFailingValidator
    {
        // Arrange
        bytes memory data = packData(EMISSARY_SMART_SESSION, testPermissionId, mockSignature);

        // Prank to intent executor
        vm.prank(MOCK_INTENT_EXECUTOR);

        // Act
        bytes4 result = smartSessionEmissary.verifyExecution(
            instance.account, TEST_HASH, data, mockExecData, testLockTag
        );

        // Assert
        assertEq(result, bytes4(0xFFFFFFFF), "Should return failure code for invalid signature");
    }

    /*//////////////////////////////////////////////////////////////
                                 CACHE
    //////////////////////////////////////////////////////////////*/

    function test_verifyExecution_CacheHit_SmartSession() public withEnabledSudoSession {
        // Arrange
        bytes memory data = packData(EMISSARY_SMART_SESSION, testPermissionId, mockSignature);

        // Prank to intent executor
        vm.prank(MOCK_INTENT_EXECUTOR);

        // First call - validates and caches
        bytes4 result1 = smartSessionEmissary.verifyExecution(
            instance.account, TEST_HASH, data, mockExecData, testLockTag
        );
        assertEq(result1, ISmartSessionEmissary.verifyExecution.selector);

        // Check cache was populated
        bool isCached = smartSessionEmissary.isDigestCachedSmartSession(
            instance.account, TEST_HASH, testPermissionId, testLockTag
        );
        assertTrue(isCached, "Digest should be cached after first verification");

        // Second call - should hit cache (no validation called)
        // We can verify by mocking the validator to fail, but cache should still return success
        vm.mockCall(
            address(yesSessionValidator),
            abi.encodeWithSelector(IStatelessValidator.validateSignatureWithData.selector),
            abi.encode(false) // Mock to return false
        );

        // Prank to intent executor
        vm.prank(MOCK_INTENT_EXECUTOR);

        // Second call - should hit cache
        bytes4 result2 = smartSessionEmissary.verifyExecution(
            instance.account, TEST_HASH, data, mockExecData, testLockTag
        );
        assertEq(result2, ISmartSessionEmissary.verifyExecution.selector);
    }

    /*//////////////////////////////////////////////////////////////
                                  EDGE
    //////////////////////////////////////////////////////////////*/

    function test_verifyExecution_InvalidMode() public {
        // Arrange
        bytes memory data = abi.encodePacked(
            bytes1(0xFF), // Invalid mode
            testPermissionId,
            mockSignature
        );

        // Prank to intent executor
        vm.prank(MOCK_INTENT_EXECUTOR);

        // Act
        bytes4 result = smartSessionEmissary.verifyExecution(
            instance.account, TEST_HASH, data, mockExecData, testLockTag
        );

        // Assert
        assertEq(result, bytes4(0xFFFFFFFF), "Should return failure code for invalid mode");
    }

    function test_verifyExecution_EmptyData() public {
        // Expect revert
        vm.expectRevert();

        // Prank to intent executor
        vm.prank(MOCK_INTENT_EXECUTOR);

        // Act
        smartSessionEmissary.verifyExecution(
            instance.account, TEST_HASH, "", mockExecData, testLockTag
        );
    }

    /*//////////////////////////////////////////////////////////////
                               MODIFIERS
    //////////////////////////////////////////////////////////////*/

    modifier withEnabledSudoSession() {
        // Prank to account
        vm.prank(instance.account);

        // Setup Sudo Policy
        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });
        ActionData[] memory actions = new ActionData[](1);
        actions[0] = ActionData({
            actionTarget: target,
            actionTargetSelector: mockTargetSelector,
            actionPolicies: policyDatas
        });

        // Empty 7739 data
        ERC7739Data memory erc7739Data;

        // Setup session
        Session memory session = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: keccak256("salt"),
            sessionValidatorInitData: "mockInitData",
            claimPolicies: new PolicyData[](0),
            erc7739Policies: erc7739Data,
            actions: actions
        });

        // Enable session
        Session[] memory sessions = new Session[](1);
        sessions[0] = session;
        smartSessionEmissary.enableSessions(sessions, testLockTag);

        // Generate the permission ID
        testPermissionId = ISmartSessionLens(address(smartSessionEmissary)).getPermissionId(session);

        // Continue with the test
        _;
    }

    modifier withEnabledBatchSudoSession() {
        // Prank to account
        vm.prank(instance.account);

        // Setup Sudo Policy for both actions
        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });

        // Create two action datas for batch execution
        ActionData[] memory actions = new ActionData[](2);
        actions[0] = ActionData({
            actionTarget: target,
            actionTargetSelector: mockTargetSelector,
            actionPolicies: policyDatas
        });
        actions[1] = ActionData({
            actionTarget: address(0x123), // Different target
            actionTargetSelector: bytes4(keccak256("anotherFunction()")),
            actionPolicies: policyDatas
        });

        // Empty 7739 data
        ERC7739Data memory erc7739Data;

        // Setup session
        Session memory session = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: keccak256("batchSalt"),
            sessionValidatorInitData: "mockInitData",
            claimPolicies: new PolicyData[](0),
            erc7739Policies: erc7739Data,
            actions: actions
        });

        // Enable session
        Session[] memory sessions = new Session[](1);
        sessions[0] = session;
        smartSessionEmissary.enableSessions(sessions, testLockTag);

        // Generate the permission ID
        testPermissionId = ISmartSessionLens(address(smartSessionEmissary)).getPermissionId(session);

        // Continue with the test
        _;
    }

    modifier withEnabledSessionWithFailingValidator() {
        // Prank to account
        vm.prank(instance.account);

        // Setup Sudo Policy
        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });
        ActionData[] memory actions = new ActionData[](1);
        actions[0] = ActionData({
            actionTarget: target,
            actionTargetSelector: mockTargetSelector,
            actionPolicies: policyDatas
        });

        // Empty 7739 data
        ERC7739Data memory erc7739Data;

        // Setup session with failing validator
        Session memory session = Session({
            sessionValidator: ISessionValidator(address(noSessionValidator)),
            salt: keccak256("failingSalt"),
            sessionValidatorInitData: "mockInitData",
            claimPolicies: new PolicyData[](0),
            erc7739Policies: erc7739Data,
            actions: actions
        });

        // Enable session
        Session[] memory sessions = new Session[](1);
        sessions[0] = session;
        smartSessionEmissary.enableSessions(sessions, testLockTag);

        // Generate the permission ID
        testPermissionId = ISmartSessionLens(address(smartSessionEmissary)).getPermissionId(session);

        // Continue with the test
        _;
    }

    modifier withNoValidator() {
        // Prank to account
        vm.prank(instance.account);

        // Install NoValidator
        instance.installModule(MODULE_TYPE_VALIDATOR, address(noValidator), "");

        // Set testValidator to noValidator
        testValidator = address(noValidator);

        // Continue with the test
        _;
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    function packData(
        EmissaryMode emissaryMode,
        PermissionId permissionId,
        bytes memory signature
    )
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(emissaryMode, permissionId, signature);
    }

    function packPermissionSig() internal view returns (bytes memory) {
        return abi.encodePacked(testValidator, "");
    }

    function createBasicSession() internal returns (Session memory session) {
        // Setup Sudo Policy
        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });
        ActionData[] memory actions = new ActionData[](1);
        actions[0] = ActionData({
            actionTarget: target,
            actionTargetSelector: mockTargetSelector,
            actionPolicies: policyDatas
        });

        // Empty 7739 data
        ERC7739Data memory erc7739Data;

        // Create a basic session
        session = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: keccak256("enableSalt"),
            sessionValidatorInitData: "mockInitData",
            claimPolicies: new PolicyData[](0),
            erc7739Policies: erc7739Data,
            actions: actions
        });

        // Calculate the permission ID
        testPermissionId = ISmartSessionLens(address(smartSessionEmissary)).getPermissionId(session);
    }
}
