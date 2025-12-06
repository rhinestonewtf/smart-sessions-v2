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
    ERC7739Context
} from "@smartsessions/DataTypes.sol";
import { Session, EnableSession, ChainDigest, NO_LOCKTAG } from "@types/DataTypes.sol";
import {
    SmartSessionEmissaryConfig,
    SmartSessionEmissaryEnable
} from "@interfaces/ISmartSessionEmissary.sol";
import { Vm } from "@forge-std/Vm.sol";
import { Scope } from "@the-compact/types/Scope.sol";
import { ResetPeriod } from "@the-compact/types/ResetPeriod.sol";

/// @title SmartSessionMixin.setConfig Unit Tests
/// @notice Unit tests for the setConfig function
contract SmartSessionMixin_setConfig_Unit_Test is SmartSessionEmissary_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using ModuleKitHelpers for *;
    using LibZip for bytes;
    using HashLibV2 for *;
    using IdLibV2 for *;
    using CompactIdLib for *;

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
        _setupTestSession();
        _setupTestConfiguration();
    }

    /*//////////////////////////////////////////////////////////////
                         BASIC SUCCESS TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test basic setConfig success
    function test_setConfig_success() public {
        // Arrange
        vm.expectEmit(true, true, false, true);
        emit SmartSessionEmissaryConfigUpdated(
            instance.account, testConfig.permissionId, testLockTag, true
        );

        // Act
        vm.prank(instance.account);
        smartSessionEmissary.setConfig(instance.account, testConfig, testEnableData);

        // Assert
        bool isEnabled = ISmartSessionLens(address(smartSessionEmissary))
            .isPermissionEnabled(instance.account, testConfig.permissionId);
        assertTrue(isEnabled);
    }

    /// @notice Test setConfig derives correct lockTag from allocator, scope, resetPeriod
    function test_setConfig_derivesCorrectLockTag() public {
        // Arrange
        bytes12 expectedLockTag =
            address(allocatorContract).deriveLockTag(testScope, testResetPeriod);

        // Act
        vm.prank(instance.account);
        smartSessionEmissary.setConfig(instance.account, testConfig, testEnableData);

        // Assert
        assertEq(testLockTag, expectedLockTag);
        bool isLockTagEnabled = ISmartSessionLens(address(smartSessionEmissary))
            .isLockTagEnabled(instance.account, testLockTag);
        assertTrue(isLockTagEnabled);
    }

    /// @notice Test setConfig increments nonce for replay protection
    function test_setConfig_incrementsNonce() public {
        // Arrange
        uint256 nonceBefore = ISmartSessionLens(address(smartSessionEmissary))
            .getNonce(instance.account, testLockTag);

        // Act
        vm.prank(instance.account);
        smartSessionEmissary.setConfig(instance.account, testConfig, testEnableData);

        // Assert
        uint256 nonceAfter = ISmartSessionLens(address(smartSessionEmissary))
            .getNonce(instance.account, testLockTag);
        assertEq(nonceAfter, nonceBefore + 1);
    }

    /// @notice Test setConfig with future timestamp
    function test_setConfig_withFutureTimestamp() public {
        // Arrange
        testExpires = block.timestamp + 1000;
        _setupTestConfiguration();

        // Act
        vm.prank(instance.account);
        smartSessionEmissary.setConfig(instance.account, testConfig, testEnableData);

        // Assert
        bool isEnabled = ISmartSessionLens(address(smartSessionEmissary))
            .isPermissionEnabled(instance.account, testConfig.permissionId);
        assertTrue(isEnabled);
    }

    /*//////////////////////////////////////////////////////////////
                         POLICY ENABLEMENT TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test setConfig with claim policies
    function test_setConfig_withClaimPolicies() public {
        // Arrange
        PolicyData[] memory claimPolicies = new PolicyData[](1);
        claimPolicies[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });
        testSession.claimPolicies = claimPolicies;

        testPermissionId = testSession.toPermissionIdMemory();
        testConfig.permissionId = testPermissionId;
        _rebuildEnableData();

        // Act
        vm.prank(instance.account);
        smartSessionEmissary.setConfig(instance.account, testConfig, testEnableData);

        // Assert
        bool isEnabled = ISmartSessionLens(address(smartSessionEmissary))
            .isPermissionEnabled(instance.account, testConfig.permissionId);
        assertTrue(isEnabled);

        bool isClaimPolicyEnabled = ISmartSessionLens(address(smartSessionEmissary))
            .isClaimPolicyEnabled(
                instance.account, testPermissionId, testLockTag, address(sudoPolicy)
            );
        assertTrue(isClaimPolicyEnabled);
    }

    /// @notice Test setConfig with ERC7739 policies
    function test_setConfig_withERC7739Policies() public {
        // Arrange
        ERC7739Context[] memory allowedContent = new ERC7739Context[](1);
        string[] memory contentNames = new string[](1);
        contentNames[0] = "TestContent";
        allowedContent[0] = ERC7739Context({
            appDomainSeparator: keccak256("TestApp"), contentNames: contentNames
        });

        PolicyData[] memory erc1271Policies = new PolicyData[](1);
        erc1271Policies[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });

        testSession.erc7739Policies = ERC7739Data({
            allowedERC7739Content: allowedContent, erc1271Policies: erc1271Policies
        });

        testPermissionId = testSession.toPermissionIdMemory();
        testConfig.permissionId = testPermissionId;
        _rebuildEnableData();

        // Act
        vm.prank(instance.account);
        smartSessionEmissary.setConfig(instance.account, testConfig, testEnableData);

        // Assert
        bool isEnabled = ISmartSessionLens(address(smartSessionEmissary))
            .isPermissionEnabled(instance.account, testConfig.permissionId);
        assertTrue(isEnabled);

        bool isERC1271PolicyEnabled = ISmartSessionLens(address(smartSessionEmissary))
            .isERC1271PolicyEnabled(instance.account, testPermissionId, address(sudoPolicy));
        assertTrue(isERC1271PolicyEnabled);
    }

    /// @notice Test setConfig with action policies
    function test_setConfig_withActionPolicies() public {
        // Arrange
        bytes4 expectedSelector = bytes4(keccak256("testFunction()"));
        ActionId expectedActionId =
            ActionId.wrap(keccak256(abi.encodePacked(target, expectedSelector)));

        // Act
        vm.prank(instance.account);
        smartSessionEmissary.setConfig(instance.account, testConfig, testEnableData);

        // Assert
        bytes32[] memory enabledActions = ISmartSessionLens(address(smartSessionEmissary))
            .getEnabledActions(instance.account, testPermissionId, testLockTag);

        assertEq(enabledActions.length, 1);
        assertEq(enabledActions[0], ActionId.unwrap(expectedActionId));

        bool isActionPolicyEnabled = ISmartSessionLens(address(smartSessionEmissary))
            .isActionPolicyEnabled(
                instance.account,
                testPermissionId,
                expectedActionId,
                testLockTag,
                address(sudoPolicy)
            );
        assertTrue(isActionPolicyEnabled);
    }

    /// @notice Test setConfig with multiple actions in session
    function test_setConfig_withMultipleActions() public {
        // Arrange
        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });

        bytes4 selector1 = bytes4(keccak256("function1()"));
        bytes4 selector2 = bytes4(keccak256("function2()"));
        bytes4 selector3 = bytes4(keccak256("function3()"));

        ActionData[] memory actions = new ActionData[](3);
        actions[0] = ActionData({
            actionTarget: target, actionTargetSelector: selector1, actionPolicies: policyDatas
        });
        actions[1] = ActionData({
            actionTarget: target, actionTargetSelector: selector2, actionPolicies: policyDatas
        });
        actions[2] = ActionData({
            actionTarget: address(0xDEAD),
            actionTargetSelector: selector3,
            actionPolicies: policyDatas
        });

        testSession.actions = actions;
        testPermissionId = testSession.toPermissionIdMemory();
        testConfig.permissionId = testPermissionId;
        _rebuildEnableData();

        // Act
        vm.prank(instance.account);
        smartSessionEmissary.setConfig(instance.account, testConfig, testEnableData);

        // Assert
        bytes32[] memory enabledActions = ISmartSessionLens(address(smartSessionEmissary))
            .getEnabledActions(instance.account, testPermissionId, testLockTag);

        assertEq(enabledActions.length, 3);

        ActionId actionId1 = ActionId.wrap(keccak256(abi.encodePacked(target, selector1)));
        ActionId actionId2 = ActionId.wrap(keccak256(abi.encodePacked(target, selector2)));
        ActionId actionId3 = ActionId.wrap(keccak256(abi.encodePacked(address(0xDEAD), selector3)));

        assertTrue(
            ISmartSessionLens(address(smartSessionEmissary))
                .isActionPolicyEnabled(
                    instance.account, testPermissionId, actionId1, testLockTag, address(sudoPolicy)
                )
        );
        assertTrue(
            ISmartSessionLens(address(smartSessionEmissary))
                .isActionPolicyEnabled(
                    instance.account, testPermissionId, actionId2, testLockTag, address(sudoPolicy)
                )
        );
        assertTrue(
            ISmartSessionLens(address(smartSessionEmissary))
                .isActionPolicyEnabled(
                    instance.account, testPermissionId, actionId3, testLockTag, address(sudoPolicy)
                )
        );
    }

    /// @notice Test setConfig with multiple policies per action
    function test_setConfig_withMultiplePoliciesPerAction() public {
        // Arrange - deploy a second policy
        SudoPolicy secondPolicy = new SudoPolicy();

        PolicyData[] memory policyDatas = new PolicyData[](2);
        policyDatas[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });
        policyDatas[1] = PolicyData({ policy: address(secondPolicy), initData: "" });

        bytes4 selector = bytes4(keccak256("testFunction()"));
        ActionData[] memory actions = new ActionData[](1);
        actions[0] = ActionData({
            actionTarget: target, actionTargetSelector: selector, actionPolicies: policyDatas
        });

        testSession.actions = actions;
        testPermissionId = testSession.toPermissionIdMemory();
        testConfig.permissionId = testPermissionId;
        _rebuildEnableData();

        // Act
        vm.prank(instance.account);
        smartSessionEmissary.setConfig(instance.account, testConfig, testEnableData);

        // Assert
        ActionId actionId = ActionId.wrap(keccak256(abi.encodePacked(target, selector)));

        assertTrue(
            ISmartSessionLens(address(smartSessionEmissary))
                .isActionPolicyEnabled(
                    instance.account, testPermissionId, actionId, testLockTag, address(sudoPolicy)
                )
        );
        assertTrue(
            ISmartSessionLens(address(smartSessionEmissary))
                .isActionPolicyEnabled(
                    instance.account, testPermissionId, actionId, testLockTag, address(secondPolicy)
                )
        );
    }

    /*//////////////////////////////////////////////////////////////
                              SCOPE TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test setConfig with ChainSpecific scope
    function test_setConfig_withChainSpecificScope() public {
        // Arrange
        assertEq(uint8(testConfig.scope), uint8(Scope.ChainSpecific));

        // Act
        vm.prank(instance.account);
        smartSessionEmissary.setConfig(instance.account, testConfig, testEnableData);

        // Assert
        bool isEnabled = ISmartSessionLens(address(smartSessionEmissary))
            .isPermissionEnabled(instance.account, testConfig.permissionId);
        assertTrue(isEnabled);
    }

    /// @notice Test setConfig with Multichain scope
    function test_setConfig_withMultichainScope() public {
        // Arrange
        testConfig.scope = Scope.Multichain;
        testLockTag = testConfig.allocator.deriveLockTag(Scope.Multichain, testConfig.resetPeriod);
        _rebuildEnableData();

        // Act
        vm.prank(instance.account);
        smartSessionEmissary.setConfig(instance.account, testConfig, testEnableData);

        // Assert
        bool isEnabled = ISmartSessionLens(address(smartSessionEmissary))
            .isPermissionEnabled(instance.account, testConfig.permissionId);
        assertTrue(isEnabled);
    }

    /*//////////////////////////////////////////////////////////////
                          RESET PERIOD TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test setConfig with OneSecond reset period
    function test_setConfig_withOneSecondResetPeriod() public {
        // Arrange
        testConfig.resetPeriod = ResetPeriod.OneSecond;
        testLockTag = testConfig.allocator.deriveLockTag(testConfig.scope, ResetPeriod.OneSecond);
        _rebuildEnableData();

        // Act
        vm.prank(instance.account);
        smartSessionEmissary.setConfig(instance.account, testConfig, testEnableData);

        // Assert
        bool isEnabled = ISmartSessionLens(address(smartSessionEmissary))
            .isPermissionEnabled(instance.account, testConfig.permissionId);
        assertTrue(isEnabled);
    }

    /// @notice Test setConfig with OneMinute reset period
    function test_setConfig_withOneMinuteResetPeriod() public {
        // Arrange
        assertEq(uint8(testConfig.resetPeriod), uint8(ResetPeriod.OneMinute));

        // Act
        vm.prank(instance.account);
        smartSessionEmissary.setConfig(instance.account, testConfig, testEnableData);

        // Assert
        bool isEnabled = ISmartSessionLens(address(smartSessionEmissary))
            .isPermissionEnabled(instance.account, testConfig.permissionId);
        assertTrue(isEnabled);
    }

    /*//////////////////////////////////////////////////////////////
                          NO_LOCKTAG TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test setConfig with NO_LOCKTAG does not require allocator sig on init
    function test_setConfig_withNoLockTag_noAllocatorSigOnInit() public {
        // Arrange
        testConfig.allocator = address(0);
        testLockTag = NO_LOCKTAG;
        _rebuildEnableData();
        testEnableData.allocatorSig = "";

        // Act
        vm.prank(instance.account);
        smartSessionEmissary.setConfig(instance.account, testConfig, testEnableData);

        // Assert
        bool isEnabled = ISmartSessionLens(address(smartSessionEmissary))
            .isPermissionEnabled(instance.account, testConfig.permissionId);
        assertTrue(isEnabled);
    }

    /// @notice Test setConfig with NO_LOCKTAG does not require allocator sig on subsequent calls
    function test_setConfig_withNoLockTag_noAllocatorSigOnSubsequentCalls() public {
        // Arrange - first enable
        testConfig.allocator = address(0);
        testLockTag = NO_LOCKTAG;
        _rebuildEnableData();
        testEnableData.allocatorSig = "";

        vm.prank(instance.account);
        smartSessionEmissary.setConfig(instance.account, testConfig, testEnableData);

        // Second enable
        _rebuildEnableData();
        testEnableData.allocatorSig = "";

        // Act
        vm.prank(instance.account);
        smartSessionEmissary.setConfig(instance.account, testConfig, testEnableData);

        // Assert
        bool isEnabled = ISmartSessionLens(address(smartSessionEmissary))
            .isPermissionEnabled(instance.account, testConfig.permissionId);
        assertTrue(isEnabled);
    }

    /// @notice Test setConfig with NO_LOCKTAG skips action and claim policy enablement
    function test_setConfig_withNoLockTag_skipsLockTagSpecificPolicies() public {
        // Arrange
        PolicyData[] memory claimPolicies = new PolicyData[](1);
        claimPolicies[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });
        testSession.claimPolicies = claimPolicies;

        testPermissionId = testSession.toPermissionIdMemory();
        testConfig.permissionId = testPermissionId;
        testConfig.allocator = address(0);
        testLockTag = NO_LOCKTAG;
        _rebuildEnableData();
        testEnableData.allocatorSig = "";

        // Act
        vm.prank(instance.account);
        smartSessionEmissary.setConfig(instance.account, testConfig, testEnableData);

        // Assert
        bool isEnabled = ISmartSessionLens(address(smartSessionEmissary))
            .isPermissionEnabled(instance.account, testConfig.permissionId);
        assertTrue(isEnabled);

        bool isClaimPolicyEnabled = ISmartSessionLens(address(smartSessionEmissary))
            .isClaimPolicyEnabled(
                instance.account, testPermissionId, NO_LOCKTAG, address(sudoPolicy)
            );
        assertFalse(isClaimPolicyEnabled);
    }

    /*//////////////////////////////////////////////////////////////
                       MULTIPLE LOCKTAGS TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test setConfig with multiple lockTags for same permissionId
    function test_setConfig_multipleLockTags() public {
        // Arrange - first enable
        vm.prank(instance.account);
        smartSessionEmissary.setConfig(instance.account, testConfig, testEnableData);

        // Create second config with different scope
        SmartSessionEmissaryConfig memory secondConfig = SmartSessionEmissaryConfig({
            permissionId: testPermissionId,
            allocator: address(allocatorContract),
            scope: Scope.Multichain,
            resetPeriod: testResetPeriod
        });

        bytes12 secondLockTag =
            secondConfig.allocator.deriveLockTag(Scope.Multichain, testResetPeriod);

        ChainDigest[] memory chainDigests = new ChainDigest[](1);
        chainDigests[0] = ChainDigest({
            chainId: uint64(block.chainid),
            sessionDigest: _getSessionDigest(testSession, secondLockTag, testExpires)
        });

        SmartSessionEmissaryEnable memory secondEnableData = SmartSessionEmissaryEnable({
            session: EnableSession({
                sessionToEnable: testSession, hashesAndChainIds: chainDigests, chainDigestIndex: 0
            }),
            expires: testExpires,
            allocatorSig: _signAllocator(chainDigests.multichainDigest()),
            userSig: ""
        });

        // Act
        vm.prank(instance.account);
        smartSessionEmissary.setConfig(instance.account, secondConfig, secondEnableData);

        // Assert
        assertTrue(
            ISmartSessionLens(address(smartSessionEmissary))
                .isLockTagEnabled(instance.account, testLockTag)
        );
        assertTrue(
            ISmartSessionLens(address(smartSessionEmissary))
                .isLockTagEnabled(instance.account, secondLockTag)
        );
    }

    /// @notice Test setConfig with different allocators derives unique lockTags
    function test_setConfig_differentAllocators_uniqueLockTags() public {
        // Arrange - first allocator
        vm.prank(instance.account);
        smartSessionEmissary.setConfig(instance.account, testConfig, testEnableData);

        // Create second allocator
        Vm.Wallet memory secondOwner = vm.createWallet("secondOwner");
        MockERC1271 secondAllocator = new MockERC1271(secondOwner.addr);

        bytes12 secondLockTag = address(secondAllocator).deriveLockTag(testScope, testResetPeriod);

        // Verify lockTags are different
        assertTrue(testLockTag != secondLockTag);

        SmartSessionEmissaryConfig memory secondConfig = SmartSessionEmissaryConfig({
            permissionId: testPermissionId,
            allocator: address(secondAllocator),
            scope: testScope,
            resetPeriod: testResetPeriod
        });

        ChainDigest[] memory chainDigests = new ChainDigest[](1);
        chainDigests[0] = ChainDigest({
            chainId: uint64(block.chainid),
            sessionDigest: _getSessionDigest(testSession, secondLockTag, testExpires)
        });

        bytes32 multichainDigest = chainDigests.multichainDigest();
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(secondOwner, multichainDigest);

        SmartSessionEmissaryEnable memory secondEnableData = SmartSessionEmissaryEnable({
            session: EnableSession({
                sessionToEnable: testSession, hashesAndChainIds: chainDigests, chainDigestIndex: 0
            }),
            expires: testExpires,
            allocatorSig: abi.encodePacked(r, s, v),
            userSig: ""
        });

        // Act
        vm.prank(instance.account);
        smartSessionEmissary.setConfig(instance.account, secondConfig, secondEnableData);

        // Assert - both lockTags enabled independently
        assertTrue(
            ISmartSessionLens(address(smartSessionEmissary))
                .isLockTagEnabled(instance.account, testLockTag)
        );
        assertTrue(
            ISmartSessionLens(address(smartSessionEmissary))
                .isLockTagEnabled(instance.account, secondLockTag)
        );
    }

    /*//////////////////////////////////////////////////////////////
                       CALLER SIGNATURE TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test setConfig when caller is account - no user sig required
    function test_setConfig_callerIsAccount_noUserSigRequired() public {
        // Arrange
        testEnableData.userSig = "";

        // Act
        vm.prank(instance.account);
        smartSessionEmissary.setConfig(instance.account, testConfig, testEnableData);

        // Assert
        bool isEnabled = ISmartSessionLens(address(smartSessionEmissary))
            .isPermissionEnabled(instance.account, testConfig.permissionId);
        assertTrue(isEnabled);
    }

    /// @notice Test setConfig when caller is not account - valid user sig succeeds
    function test_setConfig_callerNotAccount_validUserSig() public {
        // Arrange
        address differentCaller = address(0xBEEF);

        ChainDigest[] memory chainDigests = new ChainDigest[](1);
        chainDigests[0] = ChainDigest({
            chainId: uint64(block.chainid),
            sessionDigest: _getSessionDigest(testSession, testLockTag, testExpires)
        });

        bytes32 multichainDigest = chainDigests.multichainDigest();

        testEnableData.session.hashesAndChainIds = chainDigests;
        testEnableData.allocatorSig = _signAllocator(multichainDigest);
        testEnableData.userSig = _signUser(multichainDigest);

        // Act
        vm.prank(differentCaller);
        smartSessionEmissary.setConfig(instance.account, testConfig, testEnableData);

        // Assert
        bool isEnabled = ISmartSessionLens(address(smartSessionEmissary))
            .isPermissionEnabled(instance.account, testConfig.permissionId);
        assertTrue(isEnabled);
    }

    /// @notice Test setConfig when caller is not account - invalid user sig reverts
    function test_setConfig_callerNotAccount_invalidUserSig_reverts() public {
        // Arrange
        address differentCaller = address(0xBEEF);

        ChainDigest[] memory chainDigests = new ChainDigest[](1);
        chainDigests[0] = ChainDigest({
            chainId: uint64(block.chainid),
            sessionDigest: _getSessionDigest(testSession, testLockTag, testExpires)
        });

        bytes32 multichainDigest = chainDigests.multichainDigest();

        testEnableData.session.hashesAndChainIds = chainDigests;
        testEnableData.allocatorSig = _signAllocator(multichainDigest);
        testEnableData.userSig = abi.encodePacked(bytes32(0), bytes32(0), uint8(0));

        // Act & Assert
        vm.expectRevert(InvalidUserSignature.selector);
        vm.prank(differentCaller);
        smartSessionEmissary.setConfig(instance.account, testConfig, testEnableData);
    }

    /*//////////////////////////////////////////////////////////////
                     INIT VS SUBSEQUENT CALL TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test setConfig on init does not require allocator sig
    function test_setConfig_onInit_noAllocatorSigRequired() public {
        // Arrange
        testEnableData.allocatorSig = "";

        // Act
        vm.prank(instance.account);
        smartSessionEmissary.setConfig(instance.account, testConfig, testEnableData);

        // Assert
        bool isEnabled = ISmartSessionLens(address(smartSessionEmissary))
            .isPermissionEnabled(instance.account, testConfig.permissionId);
        assertTrue(isEnabled);
    }

    /// @notice Test setConfig on init adds lockTag to enabledLockTags
    function test_setConfig_onInit_addsLockTagToEnabled() public {
        // Arrange
        bool isEnabledBefore = ISmartSessionLens(address(smartSessionEmissary))
            .isLockTagEnabled(instance.account, testLockTag);
        assertFalse(isEnabledBefore);

        // Act
        vm.prank(instance.account);
        smartSessionEmissary.setConfig(instance.account, testConfig, testEnableData);

        // Assert
        bool isEnabledAfter = ISmartSessionLens(address(smartSessionEmissary))
            .isLockTagEnabled(instance.account, testLockTag);
        assertTrue(isEnabledAfter);
    }

    /// @notice Test setConfig on subsequent call requires valid allocator sig
    function test_setConfig_subsequentCall_validAllocatorSig() public {
        // Arrange - first enable
        vm.prank(instance.account);
        smartSessionEmissary.setConfig(instance.account, testConfig, testEnableData);

        // Prepare second call
        _rebuildEnableData();

        // Act
        vm.prank(instance.account);
        smartSessionEmissary.setConfig(instance.account, testConfig, testEnableData);

        // Assert
        bool isEnabled = ISmartSessionLens(address(smartSessionEmissary))
            .isPermissionEnabled(instance.account, testConfig.permissionId);
        assertTrue(isEnabled);
    }

    /// @notice Test setConfig on subsequent call with invalid allocator sig reverts
    function test_setConfig_subsequentCall_invalidAllocatorSig_reverts() public {
        // Arrange - first enable
        vm.prank(instance.account);
        smartSessionEmissary.setConfig(instance.account, testConfig, testEnableData);

        // Prepare second call with invalid sig
        _rebuildEnableData();
        testEnableData.allocatorSig =
            abi.encodePacked(bytes32(uint256(420)), bytes32(uint256(69)), uint8(27));

        // Act & Assert
        vm.expectRevert(InvalidAllocatorSignature.selector);
        vm.prank(instance.account);
        smartSessionEmissary.setConfig(instance.account, testConfig, testEnableData);
    }

    /*//////////////////////////////////////////////////////////////
                       NONCE MANAGEMENT TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test nonces are tracked independently per lockTag
    function test_setConfig_noncesIndependentPerLockTag() public {
        // Arrange - first lockTag
        vm.prank(instance.account);
        smartSessionEmissary.setConfig(instance.account, testConfig, testEnableData);

        uint256 firstLockTagNonce = ISmartSessionLens(address(smartSessionEmissary))
            .getNonce(instance.account, testLockTag);
        assertEq(firstLockTagNonce, 1);

        // Create second config with different scope (different lockTag)
        bytes12 secondLockTag =
            address(allocatorContract).deriveLockTag(Scope.Multichain, testResetPeriod);

        uint256 secondLockTagNonceBefore = ISmartSessionLens(address(smartSessionEmissary))
            .getNonce(instance.account, secondLockTag);
        assertEq(secondLockTagNonceBefore, 0);

        SmartSessionEmissaryConfig memory secondConfig = SmartSessionEmissaryConfig({
            permissionId: testPermissionId,
            allocator: address(allocatorContract),
            scope: Scope.Multichain,
            resetPeriod: testResetPeriod
        });

        ChainDigest[] memory chainDigests = new ChainDigest[](1);
        chainDigests[0] = ChainDigest({
            chainId: uint64(block.chainid),
            sessionDigest: _getSessionDigest(testSession, secondLockTag, testExpires)
        });

        SmartSessionEmissaryEnable memory secondEnableData = SmartSessionEmissaryEnable({
            session: EnableSession({
                sessionToEnable: testSession, hashesAndChainIds: chainDigests, chainDigestIndex: 0
            }),
            expires: testExpires,
            allocatorSig: _signAllocator(chainDigests.multichainDigest()),
            userSig: ""
        });

        // Act
        vm.prank(instance.account);
        smartSessionEmissary.setConfig(instance.account, secondConfig, secondEnableData);

        // Assert - each lockTag has independent nonce
        uint256 firstLockTagNonceAfter = ISmartSessionLens(address(smartSessionEmissary))
            .getNonce(instance.account, testLockTag);
        uint256 secondLockTagNonceAfter = ISmartSessionLens(address(smartSessionEmissary))
            .getNonce(instance.account, secondLockTag);

        assertEq(firstLockTagNonceAfter, 1);
        assertEq(secondLockTagNonceAfter, 1);
    }

    /*//////////////////////////////////////////////////////////////
                     SESSION VALIDATOR TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test setConfig enables session validator on first call
    function test_setConfig_enablesSessionValidator() public {
        // Act
        vm.prank(instance.account);
        smartSessionEmissary.setConfig(instance.account, testConfig, testEnableData);

        // Assert
        (address validator, bytes memory config) = ISmartSessionLens(address(smartSessionEmissary))
            .getSessionValidatorAndConfig(instance.account, testPermissionId);

        assertEq(validator, address(yesSessionValidator));
        assertEq(config, testSession.sessionValidatorInitData);
    }

    /// @notice Test setConfig on subsequent call does not change validator
    function test_setConfig_subsequentCall_validatorUnchanged() public {
        // Arrange - first enable
        vm.prank(instance.account);
        smartSessionEmissary.setConfig(instance.account, testConfig, testEnableData);

        (address validatorBefore,) = ISmartSessionLens(address(smartSessionEmissary))
            .getSessionValidatorAndConfig(instance.account, testPermissionId);

        // Second enable
        _rebuildEnableData();

        // Act
        vm.prank(instance.account);
        smartSessionEmissary.setConfig(instance.account, testConfig, testEnableData);

        // Assert
        (address validatorAfter,) = ISmartSessionLens(address(smartSessionEmissary))
            .getSessionValidatorAndConfig(instance.account, testPermissionId);
        assertEq(validatorBefore, validatorAfter);
    }

    /*//////////////////////////////////////////////////////////////
                            REVERT TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test setConfig reverts when expires is in the past
    function test_setConfig_revertsWhen_expiredInPast() public {
        // Arrange
        testEnableData.expires = block.timestamp - 1;

        // Act & Assert
        vm.expectRevert(InvalidEmissaryEnableData.selector);
        vm.prank(instance.account);
        smartSessionEmissary.setConfig(instance.account, testConfig, testEnableData);
    }

    /// @notice Test setConfig reverts when expires equals current timestamp
    function test_setConfig_revertsWhen_expiresEqualsNow() public {
        // Arrange
        testEnableData.expires = block.timestamp;

        // Act & Assert
        vm.expectRevert(InvalidEmissaryEnableData.selector);
        vm.prank(instance.account);
        smartSessionEmissary.setConfig(instance.account, testConfig, testEnableData);
    }

    /// @notice Test setConfig reverts when permissionId doesn't match session
    function test_setConfig_revertsWhen_permissionIdMismatch() public {
        // Arrange
        testConfig.permissionId = PermissionId.wrap(keccak256("wrong_permission_id"));

        // Act & Assert
        vm.expectRevert(
            abi.encodeWithSelector(InvalidPermissionId.selector, testConfig.permissionId)
        );
        vm.prank(instance.account);
        smartSessionEmissary.setConfig(instance.account, testConfig, testEnableData);
    }

    /// @notice Test setConfig reverts on nonce replay attack
    function test_setConfig_revertsWhen_nonceReplay() public {
        // Arrange - first enable
        vm.prank(instance.account);
        smartSessionEmissary.setConfig(instance.account, testConfig, testEnableData);

        // Act & Assert
        vm.expectRevert();
        vm.prank(instance.account);
        smartSessionEmissary.setConfig(instance.account, testConfig, testEnableData);
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
        return ISmartSessionLens(address(smartSessionEmissary))
            .getSessionDigest(instance.account, session, lockTag, expires);
    }

    /// @notice Setup the base test session
    function _setupTestSession() internal {
        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });

        ActionData[] memory actions = new ActionData[](1);
        actions[0] = ActionData({
            actionTarget: target,
            actionTargetSelector: bytes4(keccak256("testFunction()")),
            actionPolicies: policyDatas
        });

        ERC7739Context[] memory emptyContent = new ERC7739Context[](0);
        PolicyData[] memory emptyErc1271 = new PolicyData[](0);
        ERC7739Data memory erc7739Data =
            ERC7739Data({ allowedERC7739Content: emptyContent, erc1271Policies: emptyErc1271 });

        PolicyData[] memory emptyClaimPolicies = new PolicyData[](0);

        testSession = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: keccak256("configTestSalt"),
            sessionValidatorInitData: "configTestInitData",
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

    /// @notice Rebuild enable data with current session and config state
    function _rebuildEnableData() internal {
        ChainDigest[] memory chainDigests = new ChainDigest[](1);
        chainDigests[0] = ChainDigest({
            chainId: uint64(block.chainid),
            sessionDigest: _getSessionDigest(testSession, testLockTag, testExpires)
        });

        bytes32 multichainDigest = chainDigests.multichainDigest();

        testEnableData = SmartSessionEmissaryEnable({
            session: EnableSession({
                sessionToEnable: testSession, hashesAndChainIds: chainDigests, chainDigestIndex: 0
            }),
            expires: testExpires,
            allocatorSig: _signAllocator(multichainDigest),
            userSig: ""
        });
    }
}
