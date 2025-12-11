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
import {
    Session,
    EnableSession,
    DisableSession,
    ChainDigest,
    NO_LOCKTAG
} from "@types/DataTypes.sol";
import {
    SmartSessionEmissaryConfig,
    SmartSessionEmissaryEnable,
    SmartSessionEmissaryDisable
} from "@interfaces/ISmartSessionEmissary.sol";
import { Vm } from "@forge-std/Vm.sol";
import { Scope } from "@the-compact/types/Scope.sol";
import { ResetPeriod } from "@the-compact/types/ResetPeriod.sol";

/// @title SmartSessionMixin.removeConfig Unit Tests
/// @notice Unit tests for the removeConfig function
contract SmartSessionMixin_removeConfig_Unit_Test is SmartSessionEmissary_Unit_Test {
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
    SmartSessionEmissaryDisable testDisableData;
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

    error InvalidEmissaryDisableData();
    error InvalidAllocatorSignature();
    error InvalidUserSignature();
    error InvalidPermissionId(PermissionId permissionId);
    error HashMismatch(bytes32 providedHash, bytes32 computedHash);

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

        // Enable the session first (removeConfig requires an existing session)
        vm.prank(instance.account);
        smartSessionEmissary.setConfig(instance.account, testConfig, testEnableData);
    }

    /*//////////////////////////////////////////////////////////////
                         BASIC SUCCESS TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test basic removeConfig success
    function test_removeConfig_success() public {
        // Arrange
        _buildDisableData();

        vm.expectEmit(true, true, false, true);
        emit SmartSessionEmissaryConfigUpdated(
            instance.account, testConfig.permissionId, testLockTag, false
        );

        // Act
        vm.prank(instance.account);
        smartSessionEmissary.removeConfig(instance.account, testConfig, testDisableData);

        // Assert
        bool isEnabled = _lens().isPermissionEnabled(instance.account, testConfig.permissionId);
        assertFalse(isEnabled);
    }

    /// @notice Test removeConfig disables lockTag
    function test_removeConfig_disablesLockTag() public {
        // Arrange
        _buildDisableData();

        bool isLockTagEnabledBefore =
            _lens().isLockTagEnabled(instance.account, testPermissionId, testLockTag);
        assertTrue(isLockTagEnabledBefore);

        // Act
        vm.prank(instance.account);
        smartSessionEmissary.removeConfig(instance.account, testConfig, testDisableData);

        // Assert
        bool isLockTagEnabledAfter =
            _lens().isLockTagEnabled(instance.account, testPermissionId, testLockTag);
        assertFalse(isLockTagEnabledAfter);
    }

    /// @notice Test removeConfig increments nonce for replay protection
    function test_removeConfig_incrementsNonce() public {
        // Arrange
        _buildDisableData();

        uint256 nonceBefore = _lens().getNonce(instance.account, testLockTag);

        // Act
        vm.prank(instance.account);
        smartSessionEmissary.removeConfig(instance.account, testConfig, testDisableData);

        // Assert
        uint256 nonceAfter = _lens().getNonce(instance.account, testLockTag);
        assertEq(nonceAfter, nonceBefore + 1);
    }

    /*//////////////////////////////////////////////////////////////
                         POLICY REMOVAL TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test removeConfig removes claim policies
    function test_removeConfig_removesClaimPolicies() public {
        // Arrange - setup with claim policies
        PolicyData[] memory claimPolicies = new PolicyData[](1);
        claimPolicies[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });
        testSession.claimPolicies = claimPolicies;

        testPermissionId = testSession.toPermissionIdMemory();
        testConfig.permissionId = testPermissionId;
        _rebuildEnableData();

        // Re-enable with claim policies
        vm.prank(instance.account);
        smartSessionEmissary.setConfig(instance.account, testConfig, testEnableData);

        bool isClaimPolicyEnabledBefore = _lens()
            .isClaimPolicyEnabled(
                instance.account, testPermissionId, testLockTag, address(sudoPolicy)
            );
        assertTrue(isClaimPolicyEnabledBefore);

        // Build disable data
        _buildDisableData();

        // Act
        vm.prank(instance.account);
        smartSessionEmissary.removeConfig(instance.account, testConfig, testDisableData);

        // Assert
        bool isClaimPolicyEnabledAfter = _lens()
            .isClaimPolicyEnabled(
                instance.account, testPermissionId, testLockTag, address(sudoPolicy)
            );
        assertFalse(isClaimPolicyEnabledAfter);
    }

    /// @notice Test removeConfig removes ERC1271 policies
    function test_removeConfig_removesERC1271Policies() public {
        // Arrange - setup with ERC7739 policies
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

        // Re-enable with ERC7739 policies
        vm.prank(instance.account);
        smartSessionEmissary.setConfig(instance.account, testConfig, testEnableData);

        bool isERC1271PolicyEnabledBefore =
            _lens().isERC1271PolicyEnabled(instance.account, testPermissionId, address(sudoPolicy));
        assertTrue(isERC1271PolicyEnabledBefore);

        // Build disable data
        _buildDisableData();

        // Act
        vm.prank(instance.account);
        smartSessionEmissary.removeConfig(instance.account, testConfig, testDisableData);

        // Assert
        bool isERC1271PolicyEnabledAfter =
            _lens().isERC1271PolicyEnabled(instance.account, testPermissionId, address(sudoPolicy));
        assertFalse(isERC1271PolicyEnabledAfter);
    }

    /// @notice Test removeConfig removes action policies
    function test_removeConfig_removesActionPolicies() public {
        // Arrange
        bytes4 expectedSelector = bytes4(keccak256("testFunction()"));
        ActionId expectedActionId =
            ActionId.wrap(keccak256(abi.encodePacked(target, expectedSelector)));

        bool isActionPolicyEnabledBefore = _lens()
            .isActionPolicyEnabled(
                instance.account, testPermissionId, expectedActionId, address(sudoPolicy)
            );
        assertTrue(isActionPolicyEnabledBefore);

        _buildDisableData();

        // Act
        vm.prank(instance.account);
        smartSessionEmissary.removeConfig(instance.account, testConfig, testDisableData);

        // Assert
        bool isActionPolicyEnabledAfter = _lens()
            .isActionPolicyEnabled(
                instance.account, testPermissionId, expectedActionId, address(sudoPolicy)
            );
        assertFalse(isActionPolicyEnabledAfter);
    }

    /// @notice Test removeConfig removes all enabled actions
    function test_removeConfig_removesAllEnabledActions() public {
        // Arrange - setup with multiple actions (fresh session, not building on setUp's session)
        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });

        bytes4 selector1 = bytes4(keccak256("function1()"));
        bytes4 selector2 = bytes4(keccak256("function2()"));

        ActionData[] memory actions = new ActionData[](2);
        actions[0] = ActionData({
            actionTarget: target, actionTargetSelector: selector1, actionPolicies: policyDatas
        });
        actions[1] = ActionData({
            actionTarget: target, actionTargetSelector: selector2, actionPolicies: policyDatas
        });

        // Create a FRESH session with different salt to get a new permissionId
        ERC7739Context[] memory emptyContent = new ERC7739Context[](0);
        PolicyData[] memory emptyErc1271 = new PolicyData[](0);
        ERC7739Data memory erc7739Data =
            ERC7739Data({ allowedERC7739Content: emptyContent, erc1271Policies: emptyErc1271 });
        PolicyData[] memory emptyClaimPolicies = new PolicyData[](0);

        Session memory freshSession = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: keccak256("multipleActionsTestSalt"), // Different salt = different permissionId
            sessionValidatorInitData: "multipleActionsTestInitData",
            erc7739Policies: erc7739Data,
            claimPolicies: emptyClaimPolicies,
            actions: actions
        });

        PermissionId freshPermissionId = freshSession.toPermissionIdMemory();

        // Update config to use fresh permissionId
        testConfig.permissionId = freshPermissionId;
        testSession = freshSession;
        testPermissionId = freshPermissionId;
        _rebuildEnableData();

        // Enable the fresh session
        vm.prank(instance.account);
        smartSessionEmissary.setConfig(instance.account, testConfig, testEnableData);

        bytes32[] memory enabledActionsBefore =
            _lens().getEnabledActions(instance.account, freshPermissionId);
        assertEq(enabledActionsBefore.length, 2);

        // Build disable data
        _buildDisableData();

        // Act
        vm.prank(instance.account);
        smartSessionEmissary.removeConfig(instance.account, testConfig, testDisableData);

        // Assert
        bytes32[] memory enabledActionsAfter =
            _lens().getEnabledActions(instance.account, freshPermissionId);
        assertEq(enabledActionsAfter.length, 0);
    }

    /*//////////////////////////////////////////////////////////////
                       SESSION VALIDATOR TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test removeConfig disables session validator
    function test_removeConfig_disablesSessionValidator() public {
        // Arrange
        (address validatorBefore,) =
            _lens().getSessionValidatorAndConfig(instance.account, testPermissionId);
        assertEq(validatorBefore, address(yesSessionValidator));

        _buildDisableData();

        // Act
        vm.prank(instance.account);
        smartSessionEmissary.removeConfig(instance.account, testConfig, testDisableData);

        // Assert
        (address validatorAfter,) =
            _lens().getSessionValidatorAndConfig(instance.account, testPermissionId);
        assertEq(validatorAfter, address(0));
    }

    /*//////////////////////////////////////////////////////////////
                       CALLER SIGNATURE TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test removeConfig when caller is account - requires allocator sig
    function test_removeConfig_callerIsAccount_requiresAllocatorSig() public {
        // Arrange
        _buildDisableData();

        // Act
        vm.prank(instance.account);
        smartSessionEmissary.removeConfig(instance.account, testConfig, testDisableData);

        // Assert
        bool isEnabled = _lens().isPermissionEnabled(instance.account, testConfig.permissionId);
        assertFalse(isEnabled);
    }

    /// @notice Test removeConfig when caller is not account - valid user sig succeeds
    function test_removeConfig_callerNotAccount_validUserSig() public {
        // Arrange
        address differentCaller = address(0xBEEF);
        _buildDisableDataWithUserSig();

        // Act
        vm.prank(differentCaller);
        smartSessionEmissary.removeConfig(instance.account, testConfig, testDisableData);

        // Assert
        bool isEnabled = _lens().isPermissionEnabled(instance.account, testConfig.permissionId);
        assertFalse(isEnabled);
    }

    /// @notice Test removeConfig when caller is not account - invalid user sig reverts
    function test_removeConfig_callerNotAccount_invalidUserSig_reverts() public {
        // Arrange
        address differentCaller = address(0xBEEF);
        _buildDisableData();
        testDisableData.userSig = abi.encodePacked(bytes32(0), bytes32(0), uint8(0));

        // Act & Assert
        vm.expectRevert(InvalidUserSignature.selector);
        vm.prank(differentCaller);
        smartSessionEmissary.removeConfig(instance.account, testConfig, testDisableData);
    }

    /// @notice Test removeConfig with invalid allocator sig reverts
    function test_removeConfig_invalidAllocatorSig_reverts() public {
        // Arrange
        _buildDisableData();
        testDisableData.allocatorSig =
            abi.encodePacked(bytes32(uint256(420)), bytes32(uint256(69)), uint8(27));

        // Act & Assert
        vm.expectRevert(InvalidAllocatorSignature.selector);
        vm.prank(instance.account);
        smartSessionEmissary.removeConfig(instance.account, testConfig, testDisableData);
    }

    /*//////////////////////////////////////////////////////////////
                          NO_LOCKTAG TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test removeConfig with NO_LOCKTAG does not require allocator sig
    function test_removeConfig_withNoLockTag_noAllocatorSigRequired() public {
        // Arrange - setup with NO_LOCKTAG
        testConfig.allocator = address(0);
        testLockTag = NO_LOCKTAG;
        _rebuildEnableData();
        testEnableData.allocatorSig = "";

        // Enable first
        vm.prank(instance.account);
        smartSessionEmissary.setConfig(instance.account, testConfig, testEnableData);

        // Build disable data without allocator sig
        _buildDisableData();
        testDisableData.allocatorSig = "";

        // Act
        vm.prank(instance.account);
        smartSessionEmissary.removeConfig(instance.account, testConfig, testDisableData);

        // Assert
        bool isEnabled = _lens().isPermissionEnabled(instance.account, testConfig.permissionId);
        assertFalse(isEnabled);
    }

    /*//////////////////////////////////////////////////////////////
                       NONCE MANAGEMENT TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test nonces are tracked independently per lockTag
    function test_removeConfig_noncesIndependentPerLockTag() public {
        // Arrange - setup second lockTag
        bytes12 secondLockTag =
            address(allocatorContract).deriveLockTag(Scope.Multichain, testResetPeriod);

        SmartSessionEmissaryConfig memory secondConfig = SmartSessionEmissaryConfig({
            permissionId: testPermissionId,
            allocator: address(allocatorContract),
            scope: Scope.Multichain,
            resetPeriod: testResetPeriod
        });

        // Enable second lockTag
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
            allocatorSig: _signAllocator(this.multichainDigest(chainDigests)),
            userSig: ""
        });

        vm.prank(instance.account);
        smartSessionEmissary.setConfig(instance.account, secondConfig, secondEnableData);

        // Get nonces before
        uint256 firstLockTagNonceBefore = _lens().getNonce(instance.account, testLockTag);
        uint256 secondLockTagNonceBefore = _lens().getNonce(instance.account, secondLockTag);

        // Remove only the first config
        _buildDisableData();

        // Act
        vm.prank(instance.account);
        smartSessionEmissary.removeConfig(instance.account, testConfig, testDisableData);

        // Assert - only first lockTag nonce incremented
        uint256 firstLockTagNonceAfter = _lens().getNonce(instance.account, testLockTag);
        uint256 secondLockTagNonceAfter = _lens().getNonce(instance.account, secondLockTag);

        assertEq(firstLockTagNonceAfter, firstLockTagNonceBefore + 1);
        assertEq(secondLockTagNonceAfter, secondLockTagNonceBefore);
    }

    /*//////////////////////////////////////////////////////////////
                            REVERT TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test removeConfig reverts when expires is in the past
    function test_removeConfig_revertsWhen_expiredInPast() public {
        // Arrange
        _buildDisableData();
        testDisableData.expires = block.timestamp - 1;

        // Act & Assert
        vm.expectRevert(InvalidEmissaryDisableData.selector);
        vm.prank(instance.account);
        smartSessionEmissary.removeConfig(instance.account, testConfig, testDisableData);
    }

    /// @notice Test removeConfig reverts when expires equals current timestamp
    function test_removeConfig_revertsWhen_expiresEqualsNow() public {
        // Arrange
        _buildDisableData();
        testDisableData.expires = block.timestamp;

        // Act & Assert
        vm.expectRevert(InvalidEmissaryDisableData.selector);
        vm.prank(instance.account);
        smartSessionEmissary.removeConfig(instance.account, testConfig, testDisableData);
    }

    /// @notice Test removeConfig reverts on nonce replay attack
    function test_removeConfig_revertsWhen_nonceReplay() public {
        // Arrange - first remove
        _buildDisableData();

        vm.prank(instance.account);
        smartSessionEmissary.removeConfig(instance.account, testConfig, testDisableData);

        // Try to replay with same disable data
        // Act & Assert
        vm.expectRevert();
        vm.prank(instance.account);
        smartSessionEmissary.removeConfig(instance.account, testConfig, testDisableData);
    }

    /// @notice Test removeConfig reverts when chainId mismatches
    function test_removeConfig_revertsWhen_chainIdMismatch() public {
        // Arrange
        uint256 currentNonce = _lens().getNonce(instance.account, testLockTag);

        bytes32 disableDigest = HashLibV2.disableDigest(
            testPermissionId, instance.account, currentNonce, testExpires, testLockTag
        );

        ChainDigest[] memory chainDigests = new ChainDigest[](1);
        chainDigests[0] = ChainDigest({
            chainId: uint64(999), // Wrong chain ID
            sessionDigest: disableDigest
        });

        testDisableData = SmartSessionEmissaryDisable({
            session: DisableSession({ hashesAndChainIds: chainDigests, chainDigestIndex: 0 }),
            expires: testExpires,
            allocatorSig: _signAllocator(this.multichainDigest(chainDigests)),
            userSig: ""
        });

        // Act & Assert
        vm.expectRevert();
        vm.prank(instance.account);
        smartSessionEmissary.removeConfig(instance.account, testConfig, testDisableData);
    }

    /*//////////////////////////////////////////////////////////////
                       SCOPE & RESET PERIOD TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test removeConfig with Multichain scope
    function test_removeConfig_withMultichainScope() public {
        // Arrange - setup with Multichain scope
        testConfig.scope = Scope.Multichain;
        testLockTag = testConfig.allocator.deriveLockTag(Scope.Multichain, testConfig.resetPeriod);
        _rebuildEnableData();

        // Enable with Multichain scope
        vm.prank(instance.account);
        smartSessionEmissary.setConfig(instance.account, testConfig, testEnableData);

        // Build disable data
        _buildDisableData();

        // Act
        vm.prank(instance.account);
        smartSessionEmissary.removeConfig(instance.account, testConfig, testDisableData);

        // Assert
        bool isEnabled = _lens().isPermissionEnabled(instance.account, testConfig.permissionId);
        assertFalse(isEnabled);
    }

    /// @notice Test removeConfig with different reset periods
    function test_removeConfig_withOneSecondResetPeriod() public {
        // Arrange - setup with OneSecond reset period
        testConfig.resetPeriod = ResetPeriod.OneSecond;
        testLockTag = testConfig.allocator.deriveLockTag(testConfig.scope, ResetPeriod.OneSecond);
        _rebuildEnableData();

        // Enable with OneSecond reset period
        vm.prank(instance.account);
        smartSessionEmissary.setConfig(instance.account, testConfig, testEnableData);

        // Build disable data
        _buildDisableData();

        // Act
        vm.prank(instance.account);
        smartSessionEmissary.removeConfig(instance.account, testConfig, testDisableData);

        // Assert
        bool isEnabled = _lens().isPermissionEnabled(instance.account, testConfig.permissionId);
        assertFalse(isEnabled);
    }

    /*//////////////////////////////////////////////////////////////
                      MULTIPLE LOCKTAGS TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test removeConfig only removes specified lockTag, leaving others intact
    function test_removeConfig_onlyRemovesSpecifiedLockTag() public {
        // Arrange - setup second lockTag for SAME permissionId
        bytes12 secondLockTag =
            address(allocatorContract).deriveLockTag(Scope.Multichain, testResetPeriod);

        SmartSessionEmissaryConfig memory secondConfig = SmartSessionEmissaryConfig({
            permissionId: testPermissionId,
            allocator: address(allocatorContract),
            scope: Scope.Multichain,
            resetPeriod: testResetPeriod
        });

        // Enable second lockTag
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
            allocatorSig: _signAllocator(this.multichainDigest(chainDigests)),
            userSig: ""
        });

        vm.prank(instance.account);
        smartSessionEmissary.setConfig(instance.account, secondConfig, secondEnableData);

        // Verify both are enabled for same permissionId
        assertTrue(_lens().isLockTagEnabled(instance.account, testPermissionId, testLockTag));
        assertTrue(_lens().isLockTagEnabled(instance.account, testPermissionId, secondLockTag));

        // Remove only first lockTag
        _buildDisableData();

        // Act
        vm.prank(instance.account);
        smartSessionEmissary.removeConfig(instance.account, testConfig, testDisableData);

        // Assert - first removed, second still enabled (same permissionId)
        assertFalse(_lens().isLockTagEnabled(instance.account, testPermissionId, testLockTag));
        assertTrue(_lens().isLockTagEnabled(instance.account, testPermissionId, secondLockTag));
    }

    /*//////////////////////////////////////////////////////////////
                        LOCKTAG ISOLATION TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test removing lockTag from one permissionId doesn't affect another
    function test_removeConfig_lockTagRemovalIsolatedPerPermissionId() public {
        // Arrange - create second session with different permissionId but SAME lockTag
        Session memory secondSession = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: keccak256("differentSalt"),
            sessionValidatorInitData: "differentInitData",
            erc7739Policies: testSession.erc7739Policies,
            claimPolicies: testSession.claimPolicies,
            actions: testSession.actions
        });

        PermissionId secondPermissionId = secondSession.toPermissionIdMemory();

        SmartSessionEmissaryConfig memory secondConfig = SmartSessionEmissaryConfig({
            permissionId: secondPermissionId,
            allocator: address(allocatorContract),
            scope: testScope,
            resetPeriod: testResetPeriod
        });

        ChainDigest[] memory chainDigests = new ChainDigest[](1);
        chainDigests[0] = ChainDigest({
            chainId: uint64(block.chainid),
            sessionDigest: _getSessionDigest(secondSession, testLockTag, testExpires)
        });

        SmartSessionEmissaryEnable memory secondEnableData = SmartSessionEmissaryEnable({
            session: EnableSession({
                sessionToEnable: secondSession, hashesAndChainIds: chainDigests, chainDigestIndex: 0
            }),
            expires: testExpires,
            allocatorSig: _signAllocator(this.multichainDigest(chainDigests)),
            userSig: ""
        });

        vm.prank(instance.account);
        smartSessionEmissary.setConfig(instance.account, secondConfig, secondEnableData);

        // Verify both permissionIds have the same lockTag enabled
        assertTrue(_lens().isLockTagEnabled(instance.account, testPermissionId, testLockTag));
        assertTrue(_lens().isLockTagEnabled(instance.account, secondPermissionId, testLockTag));

        // Remove lockTag from first permissionId only
        _buildDisableData();

        // Act
        vm.prank(instance.account);
        smartSessionEmissary.removeConfig(instance.account, testConfig, testDisableData);

        // Assert - first permissionId's lockTag removed, second's intact
        assertFalse(_lens().isLockTagEnabled(instance.account, testPermissionId, testLockTag));
        assertTrue(_lens().isLockTagEnabled(instance.account, secondPermissionId, testLockTag));
    }

    /// @notice Test removing one lockTag doesn't affect other lockTags for same permissionId
    function test_removeConfig_lockTagRemovalIsolatedPerLockTag() public {
        // Arrange - setup second lockTag for SAME permissionId
        bytes12 secondLockTag =
            address(allocatorContract).deriveLockTag(Scope.Multichain, testResetPeriod);

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
            allocatorSig: _signAllocator(this.multichainDigest(chainDigests)),
            userSig: ""
        });

        vm.prank(instance.account);
        smartSessionEmissary.setConfig(instance.account, secondConfig, secondEnableData);

        // Verify both lockTags enabled for same permissionId
        assertTrue(_lens().isLockTagEnabled(instance.account, testPermissionId, testLockTag));
        assertTrue(_lens().isLockTagEnabled(instance.account, testPermissionId, secondLockTag));

        // Remove only first lockTag
        _buildDisableData();

        // Act
        vm.prank(instance.account);
        smartSessionEmissary.removeConfig(instance.account, testConfig, testDisableData);

        // Assert - first lockTag removed, second intact (same permissionId)
        assertFalse(_lens().isLockTagEnabled(instance.account, testPermissionId, testLockTag));
        assertTrue(_lens().isLockTagEnabled(instance.account, testPermissionId, secondLockTag));
    }

    /*//////////////////////////////////////////////////////////////
                        MULTICHAIN DISABLE TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test removeConfig with valid multichain data succeeds
    function test_removeConfig_multichain_validData() public {
        // Arrange
        bytes32 disableDigest = _getDisableDigest(testPermissionId, testLockTag, testExpires);

        ChainDigest[] memory chainDigests = new ChainDigest[](3);
        chainDigests[0] = ChainDigest({ chainId: 1, sessionDigest: disableDigest });
        chainDigests[1] =
            ChainDigest({ chainId: uint64(block.chainid), sessionDigest: disableDigest });
        chainDigests[2] = ChainDigest({ chainId: 42_161, sessionDigest: disableDigest });

        testDisableData = SmartSessionEmissaryDisable({
            session: DisableSession({ hashesAndChainIds: chainDigests, chainDigestIndex: 1 }),
            expires: testExpires,
            allocatorSig: _signAllocator(this.multichainDigest(chainDigests)),
            userSig: ""
        });

        // Act
        vm.prank(instance.account);
        smartSessionEmissary.removeConfig(instance.account, testConfig, testDisableData);

        // Assert
        bool isEnabled = _lens().isPermissionEnabled(instance.account, testConfig.permissionId);
        assertFalse(isEnabled);
    }

    /// @notice Test removeConfig reverts when chainDigestIndex points to wrong chain
    function test_removeConfig_multichain_revertsWhen_wrongChainDigestIndex() public {
        // Arrange
        bytes32 disableDigest = _getDisableDigest(testPermissionId, testLockTag, testExpires);

        ChainDigest[] memory chainDigests = new ChainDigest[](3);
        chainDigests[0] = ChainDigest({ chainId: 1, sessionDigest: disableDigest });
        chainDigests[1] =
            ChainDigest({ chainId: uint64(block.chainid), sessionDigest: disableDigest });
        chainDigests[2] = ChainDigest({ chainId: 42_161, sessionDigest: disableDigest });

        testDisableData = SmartSessionEmissaryDisable({
            session: DisableSession({
                hashesAndChainIds: chainDigests,
                chainDigestIndex: 2 // points to arbitrum, NOT current chain
            }),
            expires: testExpires,
            allocatorSig: _signAllocator(this.multichainDigest(chainDigests)),
            userSig: ""
        });

        // Act & Assert
        vm.expectRevert(abi.encodeWithSelector(HashLibV2.ChainIdMismatch.selector, uint64(42_161)));
        vm.prank(instance.account);
        smartSessionEmissary.removeConfig(instance.account, testConfig, testDisableData);
    }

    /// @notice Test removeConfig reverts when disable digest doesn't match
    function test_removeConfig_multichain_revertsWhen_hashMismatch() public {
        // Arrange
        bytes32 wrongDigest = keccak256("wrong");
        bytes32 correctDigest = _getDisableDigest(testPermissionId, testLockTag, testExpires);

        ChainDigest[] memory chainDigests = new ChainDigest[](1);
        chainDigests[0] =
            ChainDigest({ chainId: uint64(block.chainid), sessionDigest: wrongDigest });

        testDisableData = SmartSessionEmissaryDisable({
            session: DisableSession({ hashesAndChainIds: chainDigests, chainDigestIndex: 0 }),
            expires: testExpires,
            allocatorSig: _signAllocator(this.multichainDigest(chainDigests)),
            userSig: ""
        });

        // Act & Assert
        vm.expectRevert(
            abi.encodeWithSelector(HashLibV2.HashMismatch.selector, wrongDigest, correctDigest)
        );
        vm.prank(instance.account);
        smartSessionEmissary.removeConfig(instance.account, testConfig, testDisableData);
    }

    /// @notice Test removeConfig multichain with different digests per chain
    function test_removeConfig_multichain_differentDigestsPerChain() public {
        // Arrange - each chain could have different nonces
        bytes32 currentChainDigest = _getDisableDigest(testPermissionId, testLockTag, testExpires);
        bytes32 otherChainDigest = keccak256("otherChainDisableDigest");

        ChainDigest[] memory chainDigests = new ChainDigest[](2);
        chainDigests[0] = ChainDigest({ chainId: 1, sessionDigest: otherChainDigest });
        chainDigests[1] =
            ChainDigest({ chainId: uint64(block.chainid), sessionDigest: currentChainDigest });

        testDisableData = SmartSessionEmissaryDisable({
            session: DisableSession({ hashesAndChainIds: chainDigests, chainDigestIndex: 1 }),
            expires: testExpires,
            allocatorSig: _signAllocator(this.multichainDigest(chainDigests)),
            userSig: ""
        });

        // Act
        vm.prank(instance.account);
        smartSessionEmissary.removeConfig(instance.account, testConfig, testDisableData);

        // Assert
        bool isEnabled = _lens().isPermissionEnabled(instance.account, testConfig.permissionId);
        assertFalse(isEnabled);
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

    /// @notice Get disable digest
    function _getDisableDigest(
        PermissionId permissionId,
        bytes12 lockTag,
        uint256 expires
    )
        internal
        view
        returns (bytes32)
    {
        uint256 currentNonce = _lens().getNonce(instance.account, lockTag);
        return
            HashLibV2.disableDigest(permissionId, instance.account, currentNonce, expires, lockTag);
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
            salt: keccak256("removeConfigTestSalt"),
            sessionValidatorInitData: "removeConfigTestInitData",
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

        bytes32 multichainDigest = this.multichainDigest(chainDigests);

        testEnableData = SmartSessionEmissaryEnable({
            session: EnableSession({
                sessionToEnable: testSession, hashesAndChainIds: chainDigests, chainDigestIndex: 0
            }),
            expires: testExpires,
            allocatorSig: _signAllocator(multichainDigest),
            userSig: ""
        });
    }

    /// @notice Build disable data for current configuration
    function _buildDisableData() internal {
        bytes32 disableDigest = _getDisableDigest(testPermissionId, testLockTag, testExpires);

        ChainDigest[] memory chainDigests = new ChainDigest[](1);
        chainDigests[0] =
            ChainDigest({ chainId: uint64(block.chainid), sessionDigest: disableDigest });

        bytes32 multichainDigest = this.multichainDigest(chainDigests);

        testDisableData = SmartSessionEmissaryDisable({
            session: DisableSession({ hashesAndChainIds: chainDigests, chainDigestIndex: 0 }),
            expires: testExpires,
            allocatorSig: _signAllocator(multichainDigest),
            userSig: ""
        });
    }

    /// @notice Build disable data with user signature for non-account caller
    function _buildDisableDataWithUserSig() internal {
        bytes32 disableDigest = _getDisableDigest(testPermissionId, testLockTag, testExpires);

        ChainDigest[] memory chainDigests = new ChainDigest[](1);
        chainDigests[0] =
            ChainDigest({ chainId: uint64(block.chainid), sessionDigest: disableDigest });

        bytes32 multichainDigest = this.multichainDigest(chainDigests);

        testDisableData = SmartSessionEmissaryDisable({
            session: DisableSession({ hashesAndChainIds: chainDigests, chainDigestIndex: 0 }),
            expires: testExpires,
            allocatorSig: _signAllocator(multichainDigest),
            userSig: _signUser(multichainDigest)
        });
    }
}
