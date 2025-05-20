// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { SmartSessionExecutionVerifier_Unit_Test } from
    "@test/unit/SmartSessionExecutionVerifier/SmartSessionExecutionVerifier.t.sol";

// Interfaces
import { ISmartSessionExecutionVerifier } from "@interfaces/ISmartSessionExecutionVerifier.sol";
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
import { MODULE_TYPE_VALIDATOR } from "erc7579/interfaces/IERC7579Module.sol";

contract SmartSessionExecutionVerifier_verifyExecution_Test is
    SmartSessionExecutionVerifier_Unit_Test
{
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

    ///------------------------------------///
    /// 1. When caller is not whitelisted  ///
    ///------------------------------------///

    function test_verifyExecution_UnauthorizedSource() public {
        // Arrange
        bytes memory data = packData(SmartSessionMode.USE, testPermissionId, mockSignature);

        // Act/Assert
        vm.expectRevert(ISmartSessionExecutionVerifier.UnauthorizedSource.selector);
        smartSessionExecutionVerifier.verifyExecution(
            instance.account, TEST_HASH, data, mockExecData
        );
    }

    ///------------------------------------///
    /// 2. UseMode                         ///
    ///------------------------------------///

    function test_verifyExecution_UseMode_Success()
        public
        withWhitelistedThis
        withEnabledSudoSession
    {
        // Arrange
        bytes memory data = packData(SmartSessionMode.USE, testPermissionId, mockSignature);

        // Act
        bytes4 result = smartSessionExecutionVerifier.verifyExecution(
            instance.account, TEST_HASH, data, mockExecData
        );

        // Assert
        assertEq(
            result,
            ISmartSessionExecutionVerifier.verifyExecution.selector,
            "Should return successful verification selector"
        );
    }

    function test_verifyExecution_UseMode_InvalidPermissionId() public withWhitelistedThis {
        // Arrange
        PermissionId invalidPermissionId = PermissionId.wrap(keccak256("invalid"));
        bytes memory data = packData(SmartSessionMode.USE, invalidPermissionId, mockSignature);

        // Act/Assert
        vm.expectRevert(
            abi.encodeWithSelector(
                ISmartSessionExecutionVerifier.InvalidPermissionId.selector, invalidPermissionId
            )
        );
        smartSessionExecutionVerifier.verifyExecution(
            instance.account, TEST_HASH, data, mockExecData
        );
    }

    function test_verifyExecution_UseMode_UnsupportedSelector()
        public
        withWhitelistedThis
        withEnabledSudoSession
    {
        // Arrange
        bytes memory data = packData(SmartSessionMode.USE, testPermissionId, mockSignature);

        // Create mock data with an unsupported selector
        bytes memory unsupportedExecData =
            abi.encodeWithSelector(bytes4(keccak256("unsupportedFunction()")), "data");

        // Act/Assert
        vm.expectRevert(ISmartSessionExecutionVerifier.UnsupportedSelector.selector);
        smartSessionExecutionVerifier.verifyExecution(
            instance.account, TEST_HASH, data, unsupportedExecData
        );
    }

    function test_verifyExecution_UseMode_UnsupportedExecutionType_TryExec()
        public
        withWhitelistedThis
        withEnabledSudoSession
    {
        // Arrange
        bytes memory data = packData(SmartSessionMode.USE, testPermissionId, mockSignature);

        // Setup mock execution data with TRY execution type
        bytes memory callData = abi.encodeWithSelector(mockTargetSelector);
        ModeCode mode =
            ModeLib.encode(CALLTYPE_SINGLE, EXECTYPE_TRY, MODE_DEFAULT, ModePayload.wrap(0x00));
        bytes memory tryExecData = abi.encodeCall(
            IERC7579Account.execute, (mode, ExecutionLib.encodeSingle(target, value, callData))
        );

        // Act/Assert
        vm.expectRevert(ISmartSessionExecutionVerifier.UnsupportedExecutionType.selector);
        smartSessionExecutionVerifier.verifyExecution(
            instance.account, TEST_HASH, data, tryExecData
        );
    }

    function test_verifyExecution_UseMode_UnsupportedExecutionType_DelegateCall()
        public
        withWhitelistedThis
        withEnabledSudoSession
    {
        // Arrange
        bytes memory data = packData(SmartSessionMode.USE, testPermissionId, mockSignature);

        // Setup mock execution data with DELEGATE call type
        bytes memory callData = abi.encodeWithSelector(mockTargetSelector);
        ModeCode mode = ModeLib.encode(
            CALLTYPE_DELEGATECALL, EXECTYPE_DEFAULT, MODE_DEFAULT, ModePayload.wrap(0x00)
        );
        bytes memory delegateExecData = abi.encodeCall(
            IERC7579Account.execute, (mode, ExecutionLib.encodeSingle(target, value, callData))
        );

        // Act/Assert
        vm.expectRevert(ISmartSessionExecutionVerifier.UnsupportedExecutionType.selector);
        smartSessionExecutionVerifier.verifyExecution(
            instance.account, TEST_HASH, data, delegateExecData
        );
    }

    function test_verifyExecution_UseMode_BatchCall_Success()
        public
        withWhitelistedThis
        withEnabledBatchSudoSession
    {
        // Arrange
        bytes memory data = packData(SmartSessionMode.USE, testPermissionId, mockSignature);

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
        bytes4 result = smartSessionExecutionVerifier.verifyExecution(
            instance.account, TEST_HASH, data, batchExecData
        );

        // Assert
        assertEq(
            result,
            ISmartSessionExecutionVerifier.verifyExecution.selector,
            "Should return successful verification selector for batch execution"
        );
    }

    function test_verifyExecution_UseMode_InvalidSignature()
        public
        withWhitelistedThis
        withEnabledSessionWithFailingValidator
    {
        // Arrange
        bytes memory data = packData(SmartSessionMode.USE, testPermissionId, mockSignature);

        // Act
        bytes4 result = smartSessionExecutionVerifier.verifyExecution(
            instance.account, TEST_HASH, data, mockExecData
        );

        // Assert
        assertEq(result, bytes4(0xFFFFFFFF), "Should return failure code for invalid signature");
    }

    ///------------------------------///
    /// 3. EnableMode                ///
    ///------------------------------///

    function test_verifyExecution_EnableMode_Success() public withWhitelistedThis {
        // Arrange - Create enable session data
        Session memory session = createBasicSession();
        EnableSession memory enableData =
            makeMultiChainEnableData(testPermissionId, session, testValidator);
        bytes memory packedEnableData = encodeEnable(mockSignature, enableData);

        // Act
        bytes4 result = smartSessionExecutionVerifier.verifyExecution(
            instance.account, TEST_HASH, packedEnableData, mockExecData
        );

        // Assert
        assertEq(
            result,
            ISmartSessionExecutionVerifier.verifyExecution.selector,
            "Should return successful verification selector for enable mode"
        );

        // Verify permission was enabled
        assertTrue(
            smartSessionExecutionVerifier.isPermissionEnabled(testPermissionId, instance.account),
            "Permission should be enabled"
        );
    }

    function test_verifyExecution_EnableMode_InvalidSignature()
        public
        withWhitelistedThis
        withNoValidator
    {
        // Arrange - Create enable session data
        Session memory session = createBasicSession();
        EnableSession memory enableData =
            makeMultiChainEnableData(testPermissionId, session, testValidator);
        bytes memory packedEnableData = encodeEnable(mockSignature, enableData);

        // Expect revert due to invalid signature
        vm.expectRevert(
            abi.encodeWithSelector(
                ISmartSessionExecutionVerifier.InvalidEnableSignature.selector,
                instance.account,
                enableData.hashesAndChainIds.multichainDigest()
            )
        );

        // Act
        smartSessionExecutionVerifier.verifyExecution(
            instance.account, TEST_HASH, packedEnableData, mockExecData
        );
    }

    function test_verifyExecution_EnableMode_SessionValidatorAlreadySet()
        public
        withWhitelistedThis
    {
        // Arrange - First enable a session
        Session memory session = createBasicSession();
        EnableSession memory enableData =
            makeMultiChainEnableData(testPermissionId, session, testValidator);
        bytes memory packedEnableData = encodeEnable(mockSignature, enableData);

        // Act
        smartSessionExecutionVerifier.verifyExecution(
            instance.account, TEST_HASH, packedEnableData, mockExecData
        );

        // Create new enable data with same permissionId but different policies
        Session memory updatedSession = createBasicSession();
        // Modify the action data to be different
        updatedSession.actions[0].actionTarget = address(0x123);

        EnableSession memory updateEnableData =
            makeMultiChainEnableData(testPermissionId, updatedSession, testValidator);

        bytes memory packedUpdateData = encodeEnable(mockSignature, updateEnableData);

        // Act
        bytes4 result = smartSessionExecutionVerifier.verifyExecution(
            instance.account, TEST_HASH, packedUpdateData, mockExecData
        );

        // Assert
        assertEq(
            result,
            ISmartSessionExecutionVerifier.verifyExecution.selector,
            "Should return successful verification selector for update to existing session"
        );
    }

    function test_verifyExecution_UnsupportedMode() public withWhitelistedThis {
        bytes memory data = abi.encodePacked(uint8(3), testPermissionId, mockSignature);

        // Act/Assert
        vm.expectRevert();
        smartSessionExecutionVerifier.verifyExecution(
            instance.account, TEST_HASH, data, mockExecData
        );
    }

    /*//////////////////////////////////////////////////////////////
                               MODIFIERS
    //////////////////////////////////////////////////////////////*/

    modifier withWhitelistedThis() {
        // Prank to admin
        vm.prank(admin.addr);
        // Whitelist this contract
        smartSessionExecutionVerifier.setWhitelistedSource(address(this), true);
        // Continue with the test
        _;
    }

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
        smartSessionExecutionVerifier.enableSessions(sessions);

        // Generate the permission ID
        testPermissionId = smartSessionExecutionVerifier.getPermissionId(session);

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
        smartSessionExecutionVerifier.enableSessions(sessions);

        // Generate the permission ID
        testPermissionId = smartSessionExecutionVerifier.getPermissionId(session);

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
        smartSessionExecutionVerifier.enableSessions(sessions);

        // Generate the permission ID
        testPermissionId = smartSessionExecutionVerifier.getPermissionId(session);

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
        SmartSessionMode mode,
        PermissionId permissionId,
        bytes memory signature
    )
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(mode, permissionId, signature);
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
        testPermissionId = smartSessionExecutionVerifier.getPermissionId(session);
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
