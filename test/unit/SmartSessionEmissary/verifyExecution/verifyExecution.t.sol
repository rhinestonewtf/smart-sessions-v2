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
import { SmartExecutionLib, Execution } from "@compact-utils/common/SmartExecutionLib.sol";

// Types
import { PolicyData, ActionData, PermissionId, ERC7739Data } from "@smartsessions/DataTypes.sol";
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
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    bytes4 constant INVALID_SIGNATURE = 0xFFFFFFFF;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    PermissionId testPermissionId;
    bytes mockSignature;
    Types.Operation mockExecData;
    bytes32 testHash;
    bytes4 mockTargetSelector;
    address testValidator;
    bytes12 testLockTag = bytes12(keccak256("mockLockTag"));

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        super.setUp();

        mockSignature = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        testHash = keccak256("testHash");

        mockTargetSelector = bytes4(keccak256("testFunction()"));
        bytes memory callData = abi.encodeWithSelector(mockTargetSelector);
        Execution[] memory executions = new Execution[](1);
        executions[0] = Execution({ target: target, value: value, callData: callData });
        mockExecData = SmartExecutionLib.SigMode.EMISSARY.encode(executions);

        testValidator = address(instance.defaultValidator);

        instance.deployAccount();
    }

    /*//////////////////////////////////////////////////////////////
                            SINGLE EXECUTION
    //////////////////////////////////////////////////////////////*/

    function test_verifyExecution_SingleCall_Success() public withEnabledSudoSession {
        // Arrange
        bytes memory data = _packData(testPermissionId, mockSignature);

        // Act
        vm.prank(MOCK_INTENT_EXECUTOR);
        bytes4 result =
            smartSessionEmissary.verifyExecution(instance.account, testHash, data, mockExecData);

        // Assert
        assertEq(result, ISmartSessionEmissary.verifyExecution.selector);
    }

    function test_verifyExecution_SingleCall_InvalidSignature()
        public
        withEnabledSessionWithFailingValidator
    {
        // Arrange
        bytes memory data = _packData(testPermissionId, mockSignature);

        // Act
        vm.prank(MOCK_INTENT_EXECUTOR);
        bytes4 result =
            smartSessionEmissary.verifyExecution(instance.account, testHash, data, mockExecData);

        // Assert
        assertEq(result, INVALID_SIGNATURE);
    }

    /*//////////////////////////////////////////////////////////////
                            BATCH EXECUTION
    //////////////////////////////////////////////////////////////*/

    function test_verifyExecution_BatchCall_Success() public withEnabledBatchSudoSession {
        // Arrange
        bytes memory data = _packData(testPermissionId, mockSignature);

        Execution[] memory executions = new Execution[](2);
        executions[0] = Execution({
            target: target, value: value, callData: abi.encodeWithSelector(mockTargetSelector)
        });
        executions[1] = Execution({
            target: address(0x123),
            value: 0,
            callData: abi.encodeWithSelector(bytes4(keccak256("anotherFunction()")))
        });

        // Act
        vm.prank(MOCK_INTENT_EXECUTOR);
        bytes4 result = smartSessionEmissary.verifyExecution(
            instance.account, testHash, data, SmartExecutionLib.SigMode.EMISSARY.encode(executions)
        );

        // Assert
        assertEq(result, ISmartSessionEmissary.verifyExecution.selector);
    }

    /*//////////////////////////////////////////////////////////////
                                 CACHE
    //////////////////////////////////////////////////////////////*/

    function test_verifyExecution_CacheHit() public withEnabledSudoSession {
        // Arrange
        bytes memory data = _packData(testPermissionId, mockSignature);

        // First call - validates and caches
        vm.prank(MOCK_INTENT_EXECUTOR);
        bytes4 result1 =
            smartSessionEmissary.verifyExecution(instance.account, testHash, data, mockExecData);
        assertEq(result1, ISmartSessionEmissary.verifyExecution.selector);

        // Verify cache was populated
        bool isCached = smartSessionEmissary.isDigestCachedSmartSession(
            instance.account, testHash, testPermissionId, testLockTag
        );
        assertTrue(isCached);

        // Mock validator to fail - cache should still make it succeed
        vm.mockCall(
            address(yesSessionValidator),
            abi.encodeWithSelector(IStatelessValidator.validateSignatureWithData.selector),
            abi.encode(false)
        );

        // Second call - should hit cache
        vm.prank(MOCK_INTENT_EXECUTOR);
        bytes4 result2 =
            smartSessionEmissary.verifyExecution(instance.account, testHash, data, mockExecData);
        assertEq(result2, ISmartSessionEmissary.verifyExecution.selector);
    }

    /*//////////////////////////////////////////////////////////////
                            ACCESS CONTROL
    //////////////////////////////////////////////////////////////*/

    function test_verifyExecution_revertsWhen_CallerNotIntentExecutor()
        public
        withEnabledSudoSession
    {
        // Arrange
        bytes memory data = _packData(testPermissionId, mockSignature);
        address notIntentExecutor = makeAddr("notIntentExecutor");

        // Act & Assert
        vm.expectRevert(ISmartSessionEmissary.UnauthorizedSource.selector);
        vm.prank(notIntentExecutor);
        smartSessionEmissary.verifyExecution(instance.account, testHash, data, mockExecData);
    }

    /*//////////////////////////////////////////////////////////////
                           PERMISSION ERRORS
    //////////////////////////////////////////////////////////////*/

    function test_verifyExecution_revertsWhen_InvalidPermissionId() public {
        // Arrange
        PermissionId invalidPermissionId = PermissionId.wrap(keccak256("invalid"));
        bytes memory data = _packData(invalidPermissionId, mockSignature);

        // Act & Assert
        vm.expectRevert(
            abi.encodeWithSelector(
                ISmartSessionEmissary.InvalidPermissionId.selector, invalidPermissionId
            )
        );
        vm.prank(MOCK_INTENT_EXECUTOR);
        smartSessionEmissary.verifyExecution(instance.account, testHash, data, mockExecData);
    }

    function test_verifyExecution_revertsWhen_ActionNotEnabled() public withEnabledSudoSession {
        // Arrange - try to execute action with different selector than enabled
        bytes memory data = _packData(testPermissionId, mockSignature);

        bytes4 unauthSelector = bytes4(keccak256("unauthorizedFunction()"));
        Execution[] memory executions = new Execution[](1);
        executions[0] = Execution({
            target: target, value: 0, callData: abi.encodeWithSelector(unauthSelector)
        });

        // Act & Assert
        vm.expectRevert();
        vm.prank(MOCK_INTENT_EXECUTOR);
        smartSessionEmissary.verifyExecution(
            instance.account, testHash, data, SmartExecutionLib.SigMode.EMISSARY.encode(executions)
        );
    }

    function test_verifyExecution_revertsWhen_TargetNotEnabled() public withEnabledSudoSession {
        // Arrange - try to execute on different target than enabled
        bytes memory data = _packData(testPermissionId, mockSignature);

        address unauthorizedTarget = makeAddr("unauthorizedTarget");
        Execution[] memory executions = new Execution[](1);
        executions[0] = Execution({
            target: unauthorizedTarget,
            value: 0,
            callData: abi.encodeWithSelector(mockTargetSelector)
        });

        // Act & Assert
        vm.expectRevert();
        vm.prank(MOCK_INTENT_EXECUTOR);
        smartSessionEmissary.verifyExecution(
            instance.account, testHash, data, SmartExecutionLib.SigMode.EMISSARY.encode(executions)
        );
    }

    /*//////////////////////////////////////////////////////////////
                             EDGE CASES
    //////////////////////////////////////////////////////////////*/

    function test_verifyExecution_revertsWhen_EmptyData() public {
        // Act & Assert
        vm.expectRevert();
        vm.prank(MOCK_INTENT_EXECUTOR);
        smartSessionEmissary.verifyExecution(instance.account, testHash, "", mockExecData);
    }

    /*//////////////////////////////////////////////////////////////
                               MODIFIERS
    //////////////////////////////////////////////////////////////*/

    modifier withEnabledSudoSession() {
        vm.prank(instance.account);

        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });

        ActionData[] memory actions = new ActionData[](1);
        actions[0] = ActionData({
            actionTarget: target,
            actionTargetSelector: mockTargetSelector,
            actionPolicies: policyDatas
        });

        ERC7739Data memory erc7739Data;

        Session memory session = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: keccak256("salt"),
            sessionValidatorInitData: "mockInitData",
            claimPolicies: new PolicyData[](0),
            erc7739Policies: erc7739Data,
            actions: actions
        });

        Session[] memory sessions = new Session[](1);
        sessions[0] = session;
        smartSessionEmissary.enableSessions(sessions, testLockTag);

        testPermissionId = ISmartSessionLens(address(smartSessionEmissary)).getPermissionId(session);

        _;
    }

    modifier withEnabledBatchSudoSession() {
        vm.prank(instance.account);

        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });

        ActionData[] memory actions = new ActionData[](2);
        actions[0] = ActionData({
            actionTarget: target,
            actionTargetSelector: mockTargetSelector,
            actionPolicies: policyDatas
        });
        actions[1] = ActionData({
            actionTarget: address(0x123),
            actionTargetSelector: bytes4(keccak256("anotherFunction()")),
            actionPolicies: policyDatas
        });

        ERC7739Data memory erc7739Data;

        Session memory session = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: keccak256("batchSalt"),
            sessionValidatorInitData: "mockInitData",
            claimPolicies: new PolicyData[](0),
            erc7739Policies: erc7739Data,
            actions: actions
        });

        Session[] memory sessions = new Session[](1);
        sessions[0] = session;
        smartSessionEmissary.enableSessions(sessions, testLockTag);

        testPermissionId = ISmartSessionLens(address(smartSessionEmissary)).getPermissionId(session);

        _;
    }

    modifier withEnabledSessionWithFailingValidator() {
        vm.prank(instance.account);

        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });

        ActionData[] memory actions = new ActionData[](1);
        actions[0] = ActionData({
            actionTarget: target,
            actionTargetSelector: mockTargetSelector,
            actionPolicies: policyDatas
        });

        ERC7739Data memory erc7739Data;

        Session memory session = Session({
            sessionValidator: ISessionValidator(address(noSessionValidator)),
            salt: keccak256("failingSalt"),
            sessionValidatorInitData: "mockInitData",
            claimPolicies: new PolicyData[](0),
            erc7739Policies: erc7739Data,
            actions: actions
        });

        Session[] memory sessions = new Session[](1);
        sessions[0] = session;
        smartSessionEmissary.enableSessions(sessions, testLockTag);

        testPermissionId = ISmartSessionLens(address(smartSessionEmissary)).getPermissionId(session);

        _;
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    function _packData(
        PermissionId permissionId,
        bytes memory signature
    )
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(EMISSARY_SMART_SESSION, permissionId, signature);
    }
}
