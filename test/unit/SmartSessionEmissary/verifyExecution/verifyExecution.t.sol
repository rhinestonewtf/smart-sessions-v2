// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { SmartSessionEmissary_Unit_Test } from
    "@test/unit/SmartSessionEmissary/SmartSessionEmissary.t.sol";

// Interfaces
import { ISmartSessionEmissary } from "@interfaces/ISmartSessionEmissary.sol";
import { ISessionValidator } from "@smartsessions/interfaces/ISessionValidator.sol";
import { IERC7579Account } from "erc7579/interfaces/IERC7579Account.sol";

// Libraries
import { ExecutionLib, Execution } from "@smartsessions/lib/ExecutionLib.sol";
import { HashLib } from "@smartsessions/lib/HashLib.sol";
import { ModuleKitHelpers } from "@modulekit/ModuleKit.sol";
import { LibZip } from "solady/utils/LibZip.sol";

// Types
import {
    Session,
    PolicyData,
    ActionData,
    FALLBACK_TARGET_FLAG,
    FALLBACK_TARGET_SELECTOR_FLAG,
    PermissionId,
    SmartSessionMode,
    ActionId,
    EnableSession
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

contract SmartSessionEmissary_verifyExecution_Test is SmartSessionEmissary_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using ModuleKitHelpers for *;
    using LibZip for bytes;
    using HashLib for *;

    /*//////////////////////////////////////////////////////////////
                                 VARIABLES
    //////////////////////////////////////////////////////////////*/

    PermissionId testPermissionId;
    bytes mockSignature;
    bytes mockExecData;
    bytes32 TEST_HASH;
    bytes4 mockTargetSelector;
    address testValidator;

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
        ModeCode mode = ModeLib.encodeSimpleSingle();
        mockExecData = abi.encodeCall(
            IERC7579Account.execute, (mode, ExecutionLib.encodeSingle(target, value, callData))
        );

        // Setup testValidator as default validator
        testValidator = address(instance.defaultValidator);

        // Deploy the account instance
        instance.deployAccount();
    }

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    function test_verifyExecution_UseMode_Success() public withEnabledSudoSession {
        // Arrange
        bytes memory data =
            packData(EMISSARY_SMART_SESSION, SmartSessionMode.USE, testPermissionId, mockSignature);

        // Act
        bytes4 result =
            smartSessionEmissary.verifyExecution(instance.account, TEST_HASH, data, mockExecData);

        // Assert
        assertEq(
            result,
            ISmartSessionEmissary.verifyExecution.selector,
            "Should return successful verification selector"
        );
    }

    function test_verifyExecution_UseMode_InvalidPermissionId() public {
        // Arrange
        PermissionId invalidPermissionId = PermissionId.wrap(keccak256("invalid"));
        bytes memory data = packData(
            EMISSARY_SMART_SESSION, SmartSessionMode.USE, invalidPermissionId, mockSignature
        );

        // Act/Assert
        vm.expectRevert(
            abi.encodeWithSelector(
                ISmartSessionEmissary.InvalidPermissionId.selector, invalidPermissionId
            )
        );
        smartSessionEmissary.verifyExecution(instance.account, TEST_HASH, data, mockExecData);
    }

    function test_verifyExecution_UseMode_UnsupportedSelector() public withEnabledSudoSession {
        // Arrange
        bytes memory data =
            packData(EMISSARY_SMART_SESSION, SmartSessionMode.USE, testPermissionId, mockSignature);

        // Create mock data with an unsupported selector
        bytes memory unsupportedExecData =
            abi.encodeWithSelector(bytes4(keccak256("unsupportedFunction()")), "data");

        // Act/Assert
        vm.expectRevert(ISmartSessionEmissary.UnsupportedSelector.selector);
        smartSessionEmissary.verifyExecution(instance.account, TEST_HASH, data, unsupportedExecData);
    }

    function test_verifyExecution_UseMode_UnsupportedExecutionType_TryExec()
        public
        withEnabledSudoSession
    {
        // Arrange
        bytes memory data =
            packData(EMISSARY_SMART_SESSION, SmartSessionMode.USE, testPermissionId, mockSignature);

        // Setup mock execution data with TRY execution type
        bytes memory callData = abi.encodeWithSelector(mockTargetSelector);
        ModeCode mode =
            ModeLib.encode(CALLTYPE_SINGLE, EXECTYPE_TRY, MODE_DEFAULT, ModePayload.wrap(0x00));
        bytes memory tryExecData = abi.encodeCall(
            IERC7579Account.execute, (mode, ExecutionLib.encodeSingle(target, value, callData))
        );

        // Act/Assert
        vm.expectRevert(ISmartSessionEmissary.UnsupportedExecutionType.selector);
        smartSessionEmissary.verifyExecution(instance.account, TEST_HASH, data, tryExecData);
    }

    function test_verifyExecution_UseMode_UnsupportedExecutionType_DelegateCall()
        public
        withEnabledSudoSession
    {
        // Arrange
        bytes memory data =
            packData(EMISSARY_SMART_SESSION, SmartSessionMode.USE, testPermissionId, mockSignature);

        // Setup mock execution data with DELEGATE call type
        bytes memory callData = abi.encodeWithSelector(mockTargetSelector);
        ModeCode mode = ModeLib.encode(
            CALLTYPE_DELEGATECALL, EXECTYPE_DEFAULT, MODE_DEFAULT, ModePayload.wrap(0x00)
        );
        bytes memory delegateExecData = abi.encodeCall(
            IERC7579Account.execute, (mode, ExecutionLib.encodeSingle(target, value, callData))
        );

        // Act/Assert
        vm.expectRevert(ISmartSessionEmissary.UnsupportedExecutionType.selector);
        smartSessionEmissary.verifyExecution(instance.account, TEST_HASH, data, delegateExecData);
    }

    function test_verifyExecution_UseMode_BatchCall_Success() public withEnabledBatchSudoSession {
        // Arrange
        bytes memory data =
            packData(EMISSARY_SMART_SESSION, SmartSessionMode.USE, testPermissionId, mockSignature);

        // Create mock batch execution data
        ModeCode mode = ModeLib.encodeSimpleBatch();

        Execution[] memory executions = new Execution[](2);

        executions[0] = Execution({
            target: target,
            value: value,
            callData: abi.encodeWithSelector(mockTargetSelector)
        });

        executions[1] = Execution({
            target: address(0x123),
            value: 0,
            callData: abi.encodeWithSelector(bytes4(keccak256("anotherFunction()")))
        });

        bytes memory batchExecData =
            abi.encodeCall(IERC7579Account.execute, (mode, ExecutionLib.encodeBatch(executions)));

        // Act
        bytes4 result =
            smartSessionEmissary.verifyExecution(instance.account, TEST_HASH, data, batchExecData);

        // Assert
        assertEq(
            result,
            ISmartSessionEmissary.verifyExecution.selector,
            "Should return successful verification selector for batch execution"
        );
    }

    function test_verifyExecution_UseMode_InvalidSignature()
        public
        withEnabledSessionWithFailingValidator
    {
        // Arrange
        bytes memory data =
            packData(EMISSARY_SMART_SESSION, SmartSessionMode.USE, testPermissionId, mockSignature);

        // Act
        bytes4 result =
            smartSessionEmissary.verifyExecution(instance.account, TEST_HASH, data, mockExecData);

        // Assert
        assertEq(result, bytes4(0xFFFFFFFF), "Should return failure code for invalid signature");
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

        // Setup session
        Session memory session = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: keccak256("salt"),
            sessionValidatorInitData: "mockInitData",
            userOpPolicies: new PolicyData[](0),
            erc7739Policies: _getEmptyERC7739Data("0", new PolicyData[](0)),
            actions: actions,
            permitERC4337Paymaster: true
        });

        // Enable session
        Session[] memory sessions = new Session[](1);
        sessions[0] = session;
        smartSessionEmissary.enableSessions(sessions);

        // Generate the permission ID
        testPermissionId = smartSessionEmissary.getPermissionId(session);

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

        // Setup session
        Session memory session = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: keccak256("batchSalt"),
            sessionValidatorInitData: "mockInitData",
            userOpPolicies: new PolicyData[](0),
            erc7739Policies: _getEmptyERC7739Data("0", new PolicyData[](0)),
            actions: actions,
            permitERC4337Paymaster: true
        });

        // Enable session
        Session[] memory sessions = new Session[](1);
        sessions[0] = session;
        smartSessionEmissary.enableSessions(sessions);

        // Generate the permission ID
        testPermissionId = smartSessionEmissary.getPermissionId(session);

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

        // Setup session with failing validator
        Session memory session = Session({
            sessionValidator: ISessionValidator(address(noSessionValidator)),
            salt: keccak256("failingSalt"),
            sessionValidatorInitData: "mockInitData",
            userOpPolicies: new PolicyData[](0),
            erc7739Policies: _getEmptyERC7739Data("0", new PolicyData[](0)),
            actions: actions,
            permitERC4337Paymaster: true
        });

        // Enable session
        Session[] memory sessions = new Session[](1);
        sessions[0] = session;
        smartSessionEmissary.enableSessions(sessions);

        // Generate the permission ID
        testPermissionId = smartSessionEmissary.getPermissionId(session);

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
        SmartSessionMode sessionMode,
        PermissionId permissionId,
        bytes memory signature
    )
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(emissaryMode, sessionMode, permissionId, signature);
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

        // Create a basic session
        session = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: keccak256("enableSalt"),
            sessionValidatorInitData: "mockInitData",
            userOpPolicies: new PolicyData[](0),
            erc7739Policies: _getEmptyERC7739Data("0", new PolicyData[](0)),
            actions: actions,
            permitERC4337Paymaster: true
        });

        // Calculate the permission ID
        testPermissionId = smartSessionEmissary.getPermissionId(session);
    }

    function encodeEnable(
        bytes memory sig,
        EnableSession memory enableData
    )
        internal
        pure
        returns (bytes memory packedSig)
    {
        packedSig =
            abi.encodePacked(SmartSessionMode.ENABLE, abi.encode(enableData, sig).flzCompress());
    }
}
