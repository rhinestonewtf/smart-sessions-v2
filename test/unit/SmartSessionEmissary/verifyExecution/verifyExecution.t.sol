// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Contracts
import { SudoPolicy } from "@smartsessions/external/policies/SudoPolicy.sol";

// Dependencies
import {
    SmartSessionEmissary_Unit_Test
} from "@test/unit/SmartSessionEmissary/SmartSessionEmissary.t.sol";

// Interfaces
import { ISmartSessionEmissary } from "@interfaces/ISmartSessionEmissary.sol";
import { ISessionValidator } from "@smartsessions/interfaces/ISessionValidator.sol";
import { ISmartSessionLens } from "@interfaces/ISmartSessionLens.sol";

// Libraries
import { HashLibV2 } from "@lib/HashLibV2.sol";
import { IdLibV2 } from "@lib/IdLibV2.sol";
import { ModuleKitHelpers } from "@modulekit/ModuleKit.sol";
import { LibZip } from "solady/utils/LibZip.sol";
import { SmartExecutionLib, Execution } from "@compact-utils/common/SmartExecutionLib.sol";
import { IdLib as CompactIdLib } from "@the-compact/lib/IdLib.sol";

// Mocks
import { MockERC1271 } from "@mocks/MockERC1271.sol";

// Types
import {
    PolicyData,
    ActionData,
    PermissionId,
    ActionId,
    ERC7739Data,
    ERC7739Context,
    SmartSessionMode
} from "@smartsessions/DataTypes.sol";
import { Session, EnableSession, ChainDigest, NO_LOCKTAG } from "@types/DataTypes.sol";
import {
    SmartSessionEmissaryConfig,
    SmartSessionEmissaryEnable
} from "@interfaces/ISmartSessionEmissary.sol";
import { EMISSARY_SMART_SESSION } from "@lib/ModeLib.sol";
import { Types } from "@rhinestone/compact-utils/src/types/OrderTypes.sol";
import { Vm } from "@forge-std/Vm.sol";
import { Scope } from "@the-compact/types/Scope.sol";
import { ResetPeriod } from "@the-compact/types/ResetPeriod.sol";

/// @title SmartSessionEmissary.verifyExecution Unit Tests
/// @notice Unit tests for the verifyExecution function
contract SmartSessionEmissary_verifyExecution_Unit_Test is SmartSessionEmissary_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using ModuleKitHelpers for *;
    using LibZip for bytes;
    using HashLibV2 for *;
    using IdLibV2 for *;
    using CompactIdLib for *;
    using SmartExecutionLib for *;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    PermissionId testPermissionId;
    bytes12 testLockTag;
    Scope testScope;
    ResetPeriod testResetPeriod;
    uint256 testExpires;

    Vm.Wallet allocatorOwner;
    MockERC1271 allocatorContract;

    SmartSessionEmissaryConfig testConfig;
    SmartSessionEmissaryEnable testEnableData;
    Session testSession;

    bytes32 testHash;
    bytes4 mockTargetSelector;
    Types.Operation mockExecData;

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event SmartSessionEmissaryConfigUpdated(
        address indexed account, PermissionId permissionId, bytes12 indexed lockTag, bool enabled
    );

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidEmissaryEnableData();
    error InvalidAllocatorSignature();
    error InvalidUserSignature();
    error InvalidPermissionId(PermissionId permissionId);
    error UnsupportedSmartSessionMode(SmartSessionMode mode);

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        // Setup base
        super.setUp();

        // Deploy account instance
        instance.deployAccount();

        // Setup allocator
        allocatorOwner = vm.createWallet("allocatorOwner");
        allocatorContract = new MockERC1271(allocatorOwner.addr);

        // Setup test parameters
        testScope = Scope.ChainSpecific;
        testResetPeriod = ResetPeriod.OneMinute;
        testExpires = block.timestamp + 3600;
        testHash = keccak256("testHash");
        mockTargetSelector = bytes4(keccak256("testFunction()"));

        _setupTestSession();
        _setupTestConfiguration();
        _setupMockExecData();
    }

    /*//////////////////////////////////////////////////////////////
                     USE MODE - SINGLE EXECUTION
    //////////////////////////////////////////////////////////////*/

    /// @notice Test verifyExecution with USE mode single call succeeds
    function test_verifyExecution_UseMode_SingleCall_success() public {
        // Arrange - enable session first
        vm.prank(instance.account);
        _lens().setConfig(instance.account, testConfig, testEnableData);

        bytes memory data = _packUseData(testPermissionId, "sessionKeySig");

        // Act
        vm.prank(MOCK_INTENT_EXECUTOR);
        bytes4 result =
            smartSessionEmissary.verifyExecution(instance.account, testHash, data, mockExecData);

        // Assert
        assertEq(result, ISmartSessionEmissary.verifyExecution.selector);
    }

    /// @notice Test verifyExecution with USE mode returns invalid signature when validator rejects
    function test_verifyExecution_UseMode_SingleCall_invalidSignature() public {
        // Arrange - enable session with failing validator
        testSession.sessionValidator = ISessionValidator(address(noSessionValidator));
        testPermissionId = testSession.toPermissionIdMemory();
        testConfig.permissionId = testPermissionId;
        _rebuildEnableData();

        vm.prank(instance.account);
        _lens().setConfig(instance.account, testConfig, testEnableData);

        bytes memory data = _packUseData(testPermissionId, "sessionKeySig");

        // Act
        vm.prank(MOCK_INTENT_EXECUTOR);
        bytes4 result =
            smartSessionEmissary.verifyExecution(instance.account, testHash, data, mockExecData);

        // Assert
        assertEq(result, INVALID_SIGNATURE);
    }

    /*//////////////////////////////////////////////////////////////
                     USE MODE - BATCH EXECUTION
    //////////////////////////////////////////////////////////////*/

    /// @notice Test verifyExecution with USE mode batch call succeeds
    function test_verifyExecution_UseMode_BatchCall_success() public {
        // Arrange - enable session with multiple actions
        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });

        bytes4 selector1 = bytes4(keccak256("testFunction()"));
        bytes4 selector2 = bytes4(keccak256("anotherFunction()"));

        ActionData[] memory actions = new ActionData[](2);
        actions[0] = ActionData({
            actionTarget: target, actionTargetSelector: selector1, actionPolicies: policyDatas
        });
        actions[1] = ActionData({
            actionTarget: address(0x123),
            actionTargetSelector: selector2,
            actionPolicies: policyDatas
        });

        testSession.actions = actions;
        testPermissionId = testSession.toPermissionIdMemory();
        testConfig.permissionId = testPermissionId;
        _rebuildEnableData();

        vm.prank(instance.account);
        _lens().setConfig(instance.account, testConfig, testEnableData);

        // Build batch execution
        Execution[] memory executions = new Execution[](2);
        executions[0] = Execution({
            target: target, value: value, callData: abi.encodeWithSelector(selector1)
        });
        executions[1] = Execution({
            target: address(0x123), value: 0, callData: abi.encodeWithSelector(selector2)
        });

        Types.Operation memory batchExecData = SmartExecutionLib.SigMode.EMISSARY.encode(executions);
        bytes memory data = _packUseData(testPermissionId, "sessionKeySig");

        // Act
        vm.prank(MOCK_INTENT_EXECUTOR);
        bytes4 result =
            smartSessionEmissary.verifyExecution(instance.account, testHash, data, batchExecData);

        // Assert
        assertEq(result, ISmartSessionEmissary.verifyExecution.selector);
    }

    /// @notice Test verifyExecution with USE mode batch call reverts when one action not enabled
    function test_verifyExecution_UseMode_BatchCall_revertsWhen_oneActionNotEnabled() public {
        // Arrange - enable session with only one action
        vm.prank(instance.account);
        _lens().setConfig(instance.account, testConfig, testEnableData);

        // Build batch with second action NOT enabled
        Execution[] memory executions = new Execution[](2);
        executions[0] = Execution({
            target: target,
            value: value,
            callData: abi.encodeWithSelector(mockTargetSelector) // enabled
        });
        executions[1] = Execution({
            target: target,
            value: 0,
            callData: abi.encodeWithSelector(bytes4(keccak256("notEnabled()"))) // NOT enabled
        });

        Types.Operation memory batchExecData = SmartExecutionLib.SigMode.EMISSARY.encode(executions);
        bytes memory data = _packUseData(testPermissionId, "sessionKeySig");

        // Act & Assert
        vm.expectRevert();
        vm.prank(MOCK_INTENT_EXECUTOR);
        smartSessionEmissary.verifyExecution(instance.account, testHash, data, batchExecData);
    }

    /*//////////////////////////////////////////////////////////////
                          USE MODE - CACHE
    //////////////////////////////////////////////////////////////*/

    /// @notice Test verifyExecution caches digest after successful validation
    function test_verifyExecution_UseMode_cachesDigest() public {
        // Arrange
        vm.prank(instance.account);
        _lens().setConfig(instance.account, testConfig, testEnableData);

        bytes memory data = _packUseData(testPermissionId, "sessionKeySig");

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
    }

    /// @notice Test verifyExecution returns success from cache on second call
    function test_verifyExecution_UseMode_cacheHit() public {
        // Arrange
        vm.prank(instance.account);
        _lens().setConfig(instance.account, testConfig, testEnableData);

        bytes memory data = _packUseData(testPermissionId, "sessionKeySig");

        // First call
        vm.prank(MOCK_INTENT_EXECUTOR);
        smartSessionEmissary.verifyExecution(instance.account, testHash, data, mockExecData);

        // Second call - should hit cache even with different signature
        bytes memory data2 = _packUseData(testPermissionId, "differentSig");

        vm.prank(MOCK_INTENT_EXECUTOR);
        bytes4 result =
            smartSessionEmissary.verifyExecution(instance.account, testHash, data2, mockExecData);

        assertEq(result, ISmartSessionEmissary.verifyExecution.selector);
    }

    /// @notice Test cache is isolated per account
    function test_verifyExecution_UseMode_cacheIsolatedPerAccount() public {
        // Arrange
        vm.prank(instance.account);
        _lens().setConfig(instance.account, testConfig, testEnableData);

        bytes memory data = _packUseData(testPermissionId, "sessionKeySig");

        // First call - validates and caches for instance.account
        vm.prank(MOCK_INTENT_EXECUTOR);
        smartSessionEmissary.verifyExecution(instance.account, testHash, data, mockExecData);

        // Verify cache was populated for instance.account
        bool isCachedForOriginal = smartSessionEmissary.isDigestCachedSmartSession(
            instance.account, testHash, testPermissionId, testLockTag
        );
        assertTrue(isCachedForOriginal, "Should be cached for original account");

        // Verify cache is NOT populated for different account
        address differentAccount = makeAddr("differentAccount");
        bool isCachedForDifferent = smartSessionEmissary.isDigestCachedSmartSession(
            differentAccount, testHash, testPermissionId, testLockTag
        );
        assertFalse(isCachedForDifferent, "Should NOT be cached for different account");
    }

    /// @notice Test cache is isolated per permissionId
    function test_verifyExecution_UseMode_cacheIsolatedPerPermissionId() public {
        // Arrange
        vm.prank(instance.account);
        _lens().setConfig(instance.account, testConfig, testEnableData);

        bytes memory data = _packUseData(testPermissionId, "sessionKeySig");

        // First call - validates and caches
        vm.prank(MOCK_INTENT_EXECUTOR);
        smartSessionEmissary.verifyExecution(instance.account, testHash, data, mockExecData);

        // Verify cache was populated for testPermissionId
        bool isCachedForOriginal = smartSessionEmissary.isDigestCachedSmartSession(
            instance.account, testHash, testPermissionId, testLockTag
        );
        assertTrue(isCachedForOriginal, "Should be cached for original permissionId");

        // Verify cache is NOT populated for different permissionId
        PermissionId differentPermissionId = PermissionId.wrap(keccak256("different"));
        bool isCachedForDifferent = smartSessionEmissary.isDigestCachedSmartSession(
            instance.account, testHash, differentPermissionId, testLockTag
        );
        assertFalse(isCachedForDifferent, "Should NOT be cached for different permissionId");
    }

    /*//////////////////////////////////////////////////////////////
                     USE MODE - ACCESS CONTROL
    //////////////////////////////////////////////////////////////*/

    /// @notice Test verifyExecution reverts when caller is not intent executor
    function test_verifyExecution_UseMode_revertsWhen_callerNotIntentExecutor() public {
        // Arrange
        vm.prank(instance.account);
        _lens().setConfig(instance.account, testConfig, testEnableData);

        bytes memory data = _packUseData(testPermissionId, "sessionKeySig");
        address notIntentExecutor = makeAddr("notIntentExecutor");

        // Act & Assert
        vm.expectRevert(ISmartSessionEmissary.UnauthorizedSource.selector);
        vm.prank(notIntentExecutor);
        smartSessionEmissary.verifyExecution(instance.account, testHash, data, mockExecData);
    }

    /// @notice Test verifyExecution reverts when permissionId is invalid
    function test_verifyExecution_UseMode_revertsWhen_invalidPermissionId() public {
        // Arrange - don't enable any session
        PermissionId invalidPermissionId = PermissionId.wrap(keccak256("invalid"));
        bytes memory data = _packUseData(invalidPermissionId, "sessionKeySig");

        // Act & Assert
        vm.expectRevert(abi.encodeWithSelector(InvalidPermissionId.selector, invalidPermissionId));
        vm.prank(MOCK_INTENT_EXECUTOR);
        smartSessionEmissary.verifyExecution(instance.account, testHash, data, mockExecData);
    }

    /// @notice Test verifyExecution reverts when action selector is not enabled
    function test_verifyExecution_UseMode_revertsWhen_actionNotEnabled() public {
        // Arrange
        vm.prank(instance.account);
        _lens().setConfig(instance.account, testConfig, testEnableData);

        bytes4 unauthSelector = bytes4(keccak256("unauthorizedFunction()"));
        Execution[] memory executions = new Execution[](1);
        executions[0] = Execution({
            target: target, value: 0, callData: abi.encodeWithSelector(unauthSelector)
        });

        Types.Operation memory unauthExecData =
            SmartExecutionLib.SigMode.EMISSARY.encode(executions);
        bytes memory data = _packUseData(testPermissionId, "sessionKeySig");

        // Act & Assert
        vm.expectRevert();
        vm.prank(MOCK_INTENT_EXECUTOR);
        smartSessionEmissary.verifyExecution(instance.account, testHash, data, unauthExecData);
    }

    /// @notice Test verifyExecution reverts when target is not enabled
    function test_verifyExecution_UseMode_revertsWhen_targetNotEnabled() public {
        // Arrange
        vm.prank(instance.account);
        _lens().setConfig(instance.account, testConfig, testEnableData);

        address unauthorizedTarget = makeAddr("unauthorizedTarget");
        Execution[] memory executions = new Execution[](1);
        executions[0] = Execution({
            target: unauthorizedTarget,
            value: 0,
            callData: abi.encodeWithSelector(mockTargetSelector)
        });

        Types.Operation memory unauthExecData =
            SmartExecutionLib.SigMode.EMISSARY.encode(executions);
        bytes memory data = _packUseData(testPermissionId, "sessionKeySig");

        // Act & Assert
        vm.expectRevert();
        vm.prank(MOCK_INTENT_EXECUTOR);
        smartSessionEmissary.verifyExecution(instance.account, testHash, data, unauthExecData);
    }

    /// @notice Test verifyExecution reverts when emissary data is empty
    function test_verifyExecution_UseMode_revertsWhen_emptyData() public {
        // Act & Assert
        vm.expectRevert();
        vm.prank(MOCK_INTENT_EXECUTOR);
        smartSessionEmissary.verifyExecution(instance.account, testHash, "", mockExecData);
    }

    /*//////////////////////////////////////////////////////////////
                       USE MODE - ISOLATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Test action policies are isolated per account
    function test_verifyExecution_UseMode_isolatedPerAccount() public {
        // Arrange
        vm.prank(instance.account);
        _lens().setConfig(instance.account, testConfig, testEnableData);

        bytes memory data = _packUseData(testPermissionId, "sessionKeySig");
        address differentAccount = makeAddr("differentAccount");

        // Act & Assert - should fail because session not enabled for different account
        vm.expectRevert(abi.encodeWithSelector(InvalidPermissionId.selector, testPermissionId));
        vm.prank(MOCK_INTENT_EXECUTOR);
        smartSessionEmissary.verifyExecution(differentAccount, testHash, data, mockExecData);
    }

    /// @notice Test action policies are isolated per permissionId
    function test_verifyExecution_UseMode_isolatedPerPermissionId() public {
        // Arrange - enable first session
        vm.prank(instance.account);
        _lens().setConfig(instance.account, testConfig, testEnableData);

        // Create second session with different salt (different permissionId)
        Session memory session2 = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: keccak256("differentSalt"),
            sessionValidatorInitData: "differentInitData",
            erc7739Policies: testSession.erc7739Policies,
            claimPolicies: testSession.claimPolicies,
            actions: _createDifferentActions() // Different selector
        });

        PermissionId permissionId2 = session2.toPermissionIdMemory();

        SmartSessionEmissaryConfig memory config2 = SmartSessionEmissaryConfig({
            permissionId: permissionId2,
            allocator: address(allocatorContract),
            scope: testScope,
            resetPeriod: testResetPeriod
        });

        ChainDigest[] memory chainDigests2 = new ChainDigest[](1);
        chainDigests2[0] = ChainDigest({
            chainId: uint64(block.chainid),
            sessionDigest: _getSessionDigest(session2, testLockTag, testExpires)
        });

        SmartSessionEmissaryEnable memory enableData2 = SmartSessionEmissaryEnable({
            session: EnableSession({
                sessionToEnable: session2, hashesAndChainIds: chainDigests2, chainDigestIndex: 0
            }),
            expires: testExpires,
            allocatorSig: _signAllocator(this.multichainDigest(chainDigests2)),
            userSig: ""
        });

        vm.prank(instance.account);
        _lens().setConfig(instance.account, config2, enableData2);

        // Try to execute mockTargetSelector (from first session) using permissionId2
        bytes memory data = _packUseData(permissionId2, "sessionKeySig");

        // Act & Assert - should fail because mockTargetSelector not enabled for permissionId2
        vm.expectRevert();
        vm.prank(MOCK_INTENT_EXECUTOR);
        smartSessionEmissary.verifyExecution(instance.account, testHash, data, mockExecData);
    }

    /// @notice Test action policies are isolated per actionId (target + selector combo)
    function test_verifyExecution_UseMode_isolatedPerActionId() public {
        // Arrange
        vm.prank(instance.account);
        _lens().setConfig(instance.account, testConfig, testEnableData);

        // Same target, different selector
        bytes4 wrongSelector = bytes4(keccak256("wrongFunction()"));
        Execution[] memory executions = new Execution[](1);
        executions[0] = Execution({
            target: target, value: 0, callData: abi.encodeWithSelector(wrongSelector)
        });

        Types.Operation memory wrongExecData = SmartExecutionLib.SigMode.EMISSARY.encode(executions);
        bytes memory data = _packUseData(testPermissionId, "sessionKeySig");

        // Act & Assert
        vm.expectRevert();
        vm.prank(MOCK_INTENT_EXECUTOR);
        smartSessionEmissary.verifyExecution(instance.account, testHash, data, wrongExecData);
    }

    /// @notice Test action policies are isolated per target
    function test_verifyExecution_UseMode_isolatedPerTarget() public {
        // Arrange
        vm.prank(instance.account);
        _lens().setConfig(instance.account, testConfig, testEnableData);

        // Different target, same selector
        address wrongTarget = makeAddr("wrongTarget");
        Execution[] memory executions = new Execution[](1);
        executions[0] = Execution({
            target: wrongTarget, value: 0, callData: abi.encodeWithSelector(mockTargetSelector)
        });

        Types.Operation memory wrongExecData = SmartExecutionLib.SigMode.EMISSARY.encode(executions);
        bytes memory data = _packUseData(testPermissionId, "sessionKeySig");

        // Act & Assert
        vm.expectRevert();
        vm.prank(MOCK_INTENT_EXECUTOR);
        smartSessionEmissary.verifyExecution(instance.account, testHash, data, wrongExecData);
    }

    /*//////////////////////////////////////////////////////////////
                       ENABLE MODE - SUCCESS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test verifyExecution with ENABLE mode enables session and succeeds
    function test_verifyExecution_EnableMode_success() public {
        // Arrange - build enable mode data (session not pre-enabled)
        bytes memory enableModeData = _packEnableData(testEnableData, testConfig, "sessionKeySig");

        // Verify session is NOT enabled before
        bool isEnabledBefore = _lens().isPermissionEnabled(instance.account, testPermissionId);
        assertFalse(isEnabledBefore);

        // Act
        vm.prank(MOCK_INTENT_EXECUTOR);
        bytes4 result = smartSessionEmissary.verifyExecution(
            instance.account, testHash, enableModeData, mockExecData
        );

        // Assert
        assertEq(result, ISmartSessionEmissary.verifyExecution.selector);

        // Verify session is now enabled
        bool isEnabledAfter = _lens().isPermissionEnabled(instance.account, testPermissionId);
        assertTrue(isEnabledAfter);
    }

    /// @notice Test verifyExecution with ENABLE mode reverts when enable data expired
    function test_verifyExecution_EnableMode_revertsWhen_expired() public {
        // Arrange - create enable data with expired timestamp
        testEnableData.expires = block.timestamp - 1;

        bytes memory enableModeData = _packEnableData(testEnableData, testConfig, "sessionKeySig");

        // Act & Assert
        vm.expectRevert(InvalidEmissaryEnableData.selector);
        vm.prank(MOCK_INTENT_EXECUTOR);
        smartSessionEmissary.verifyExecution(
            instance.account, testHash, enableModeData, mockExecData
        );
    }

    /// @notice Test verifyExecution with ENABLE mode reverts when permissionId mismatch
    function test_verifyExecution_EnableMode_revertsWhen_permissionIdMismatch() public {
        // Arrange - config has wrong permissionId
        testConfig.permissionId = PermissionId.wrap(keccak256("wrong_permission_id"));

        bytes memory enableModeData = _packEnableData(testEnableData, testConfig, "sessionKeySig");

        // Act & Assert
        vm.expectRevert(
            abi.encodeWithSelector(InvalidPermissionId.selector, testConfig.permissionId)
        );
        vm.prank(MOCK_INTENT_EXECUTOR);
        smartSessionEmissary.verifyExecution(
            instance.account, testHash, enableModeData, mockExecData
        );
    }

    /// @notice Test verifyExecution with ENABLE mode reverts when user signature invalid
    function test_verifyExecution_EnableMode_revertsWhen_invalidUserSig() public {
        // Arrange - enable from different caller with invalid user sig
        address differentCaller = makeAddr("differentCaller");

        ChainDigest[] memory chainDigests = new ChainDigest[](1);
        chainDigests[0] = ChainDigest({
            chainId: uint64(block.chainid),
            sessionDigest: _getSessionDigest(testSession, testLockTag, testExpires)
        });

        testEnableData.session.hashesAndChainIds = chainDigests;
        testEnableData.allocatorSig = _signAllocator(this.multichainDigest(chainDigests));
        testEnableData.userSig = hex"deadbeef"; // Invalid

        bytes memory enableModeData = _packEnableData(testEnableData, testConfig, "sessionKeySig");

        // Act & Assert
        vm.expectRevert(InvalidUserSignature.selector);
        vm.prank(MOCK_INTENT_EXECUTOR);
        smartSessionEmissary.verifyExecution(
            instance.account, testHash, enableModeData, mockExecData
        );
    }

    /*//////////////////////////////////////////////////////////////
                 ENABLE MODE - RE-ENABLE (WITH ALLOCATOR)
    //////////////////////////////////////////////////////////////*/

    /// @notice Test verifyExecution with ENABLE mode re-enable with valid allocator sig
    function test_verifyExecution_EnableMode_reEnable_success() public {
        // Arrange - first enable via setConfig
        vm.prank(instance.account);
        _lens().setConfig(instance.account, testConfig, testEnableData);

        // Prepare second enable (re-enable requires allocator sig)
        _rebuildEnableData();

        bytes memory enableModeData = _packEnableData(testEnableData, testConfig, "sessionKeySig");

        // Act
        vm.prank(MOCK_INTENT_EXECUTOR);
        bytes4 result = smartSessionEmissary.verifyExecution(
            instance.account, keccak256("newHash"), enableModeData, mockExecData
        );

        // Assert
        assertEq(result, ISmartSessionEmissary.verifyExecution.selector);
    }

    /// @notice Test verifyExecution with ENABLE mode re-enable reverts with invalid allocator sig
    function test_verifyExecution_EnableMode_reEnable_revertsWhen_invalidAllocatorSig() public {
        // Arrange - first enable via setConfig
        vm.prank(instance.account);
        _lens().setConfig(instance.account, testConfig, testEnableData);

        // Prepare second enable with invalid allocator sig
        _rebuildEnableData();
        testEnableData.allocatorSig = hex"deadbeef";

        bytes memory enableModeData = _packEnableData(testEnableData, testConfig, "sessionKeySig");

        // Act & Assert
        vm.expectRevert(InvalidAllocatorSignature.selector);
        vm.prank(MOCK_INTENT_EXECUTOR);
        smartSessionEmissary.verifyExecution(
            instance.account, keccak256("newHash"), enableModeData, mockExecData
        );
    }

    /*//////////////////////////////////////////////////////////////
                    ENABLE MODE - NO_LOCKTAG FLOW
    //////////////////////////////////////////////////////////////*/

    /// @notice Test verifyExecution with ENABLE mode NO_LOCKTAG succeeds without allocator
    function test_verifyExecution_EnableMode_noLockTag_success() public {
        // Arrange - config with no allocator (NO_LOCKTAG flow)
        testConfig.allocator = address(0);
        testLockTag = NO_LOCKTAG;
        _rebuildEnableData();
        testEnableData.allocatorSig = "";

        bytes memory enableModeData = _packEnableData(testEnableData, testConfig, "sessionKeySig");

        // Act
        vm.prank(MOCK_INTENT_EXECUTOR);
        bytes4 result = smartSessionEmissary.verifyExecution(
            instance.account, testHash, enableModeData, mockExecData
        );

        // Assert
        assertEq(result, ISmartSessionEmissary.verifyExecution.selector);

        // Verify session enabled
        bool isEnabled = _lens().isPermissionEnabled(instance.account, testPermissionId);
        assertTrue(isEnabled);
    }

    /*//////////////////////////////////////////////////////////////
                        UNSUPPORTED MODE
    //////////////////////////////////////////////////////////////*/

    /// @notice Test verifyExecution reverts with unsupported mode (UNSAFE_ENABLE)
    function test_verifyExecution_revertsWhen_unsupportedMode() public {
        // Arrange - pack data with UNSAFE_ENABLE mode
        bytes memory data = abi.encodePacked(
            SmartSessionMode.UNSAFE_ENABLE,
            testPermissionId,
            "sessionKeySig17237123712737123717231723717237172317237172371371723"
        );

        // Act & Assert
        vm.expectRevert(
            abi.encodeWithSelector(
                UnsupportedSmartSessionMode.selector, SmartSessionMode.UNSAFE_ENABLE
            )
        );
        vm.prank(MOCK_INTENT_EXECUTOR);
        smartSessionEmissary.verifyExecution(instance.account, testHash, data, mockExecData);
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Sign hash with allocator owner's EOA key for ERC-1271 verification
    function _signAllocator(bytes32 hash) internal returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(allocatorOwner, hash);
        return abi.encodePacked(r, s, v);
    }

    /// @notice Sign hash for user's smart account via ERC-1271
    function _signUser(bytes32 hash) internal view returns (bytes memory) {
        return abi.encodePacked(address(instance.defaultValidator), hash);
    }

    /// @notice Get session digest from the emissary
    function _getSessionDigest(
        Session memory session,
        bytes12 lockTag,
        uint256 expires
    )
        internal
        view
        returns (bytes32)
    {
        return _lens().getSessionDigest(instance.account, session, lockTag, expires);
    }

    /// @notice Setup the base test session
    function _setupTestSession() internal {
        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });

        ActionData[] memory actions = new ActionData[](1);
        actions[0] = ActionData({
            actionTarget: target,
            actionTargetSelector: mockTargetSelector,
            actionPolicies: policyDatas
        });

        ERC7739Context[] memory emptyContent = new ERC7739Context[](0);
        PolicyData[] memory emptyErc1271 = new PolicyData[](0);
        ERC7739Data memory erc7739Data =
            ERC7739Data({ allowedERC7739Content: emptyContent, erc1271Policies: emptyErc1271 });

        PolicyData[] memory emptyClaimPolicies = new PolicyData[](0);

        testSession = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: keccak256("verifyExecutionTestSalt"),
            sessionValidatorInitData: "verifyExecutionTestInitData",
            erc7739Policies: erc7739Data,
            claimPolicies: emptyClaimPolicies,
            actions: actions
        });

        testPermissionId = testSession.toPermissionIdMemory();
    }

    /// @notice Setup the test configuration
    function _setupTestConfiguration() internal {
        testLockTag = address(allocatorContract).deriveLockTag(testScope, testResetPeriod);

        testConfig = SmartSessionEmissaryConfig({
            permissionId: testPermissionId,
            allocator: address(allocatorContract),
            scope: testScope,
            resetPeriod: testResetPeriod
        });

        _rebuildEnableData();
    }

    /// @notice Setup mock execution data
    function _setupMockExecData() internal {
        Execution[] memory executions = new Execution[](1);
        executions[0] = Execution({
            target: target, value: value, callData: abi.encodeWithSelector(mockTargetSelector)
        });
        mockExecData = SmartExecutionLib.SigMode.EMISSARY.encode(executions);
    }

    /// @notice Rebuild enable data with current session and config state
    function _rebuildEnableData() internal {
        ChainDigest[] memory chainDigests = new ChainDigest[](1);
        chainDigests[0] = ChainDigest({
            chainId: uint64(block.chainid),
            sessionDigest: _getSessionDigest(testSession, testLockTag, testExpires)
        });

        bytes32 multichainDigest = this.multichainDigest(chainDigests);

        testEnableData = SmartSessionEmissaryEnable({
            session: EnableSession({
                sessionToEnable: testSession, hashesAndChainIds: chainDigests, chainDigestIndex: 0
            }),
            expires: testExpires,
            allocatorSig: _signAllocator(multichainDigest),
            userSig: _signUser(multichainDigest)
        });
    }

    /// @notice Pack USE mode data
    function _packUseData(
        PermissionId permissionId,
        bytes memory signature
    )
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(SmartSessionMode.USE, permissionId, signature);
    }

    /// @notice Pack ENABLE mode data with compression
    function _packEnableData(
        SmartSessionEmissaryEnable memory enableData,
        SmartSessionEmissaryConfig memory config,
        bytes memory usePermissionSig
    )
        internal
        pure
        returns (bytes memory)
    {
        bytes memory compressed = abi.encode(enableData, config, usePermissionSig).flzCompress();
        return abi.encodePacked(SmartSessionMode.ENABLE, compressed);
    }

    /// @notice Create different actions for isolation test
    function _createDifferentActions() internal view returns (ActionData[] memory) {
        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });

        bytes4 differentSelector = bytes4(keccak256("differentFunction()"));

        ActionData[] memory actions = new ActionData[](1);
        actions[0] = ActionData({
            actionTarget: target,
            actionTargetSelector: differentSelector,
            actionPolicies: policyDatas
        });

        return actions;
    }
}
