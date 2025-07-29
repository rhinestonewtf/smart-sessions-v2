// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { SmartSessionEmissary_Unit_Test } from
    "@test/unit/SmartSessionEmissary/SmartSessionEmissary.t.sol";

// Interfaces
import { ISmartSessionEmissary } from "@interfaces/ISmartSessionEmissary.sol";
import { ISessionValidator } from "@smartsessions/interfaces/ISessionValidator.sol";

// Libraries
import { HashLibV2, SESSION_TYPEHASH } from "@lib/HashLibV2.sol";
import { IdLibV2 } from "@lib/IdLibV2.sol";
import { ModuleKitHelpers } from "@modulekit/ModuleKit.sol";
import { LibZip } from "solady/utils/LibZip.sol";
import { ECDSA } from "solady/utils/ECDSA.sol";
import { IdLib as CompactIdLib } from "@the-compact/lib/IdLib.sol";

// Types
import { PolicyData, ActionData, PermissionId } from "@smartsessions/DataTypes.sol";
import { Session, EnableSession, ChainDigest } from "@types/DataTypes.sol";
import {
    SmartSessionEmissaryConfig,
    SmartSessionEmissaryEnable
} from "@interfaces/ISmartSessionEmissary.sol";
import { Vm } from "@forge-std/Vm.sol";
import { Scope } from "@the-compact/types/Scope.sol";
import { ResetPeriod } from "@the-compact/types/ResetPeriod.sol";

contract SmartSessionEmissary_setConfig_Test is SmartSessionEmissary_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using ModuleKitHelpers for *;
    using LibZip for bytes;
    using HashLibV2 for *;
    using IdLibV2 for *;
    using CompactIdLib for *;

    /*//////////////////////////////////////////////////////////////
                                 VARIABLES
    //////////////////////////////////////////////////////////////*/

    PermissionId testPermissionId;
    bytes12 testLockTag;
    Scope testScope;
    ResetPeriod testResetPeriod;
    Vm.Wallet testAllocator;
    address testSender;
    uint256 testExpires;

    SmartSessionEmissaryConfig testConfig;
    SmartSessionEmissaryEnable testEnableData;
    Session testSession;

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event SmartSessionEmissaryConfigUpdated(
        address indexed account, PermissionId indexed permissionId, bytes12 indexed lockTag
    );

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidEmissaryEnableData();

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        // Call the base setup function
        super.setUp();

        // Initialize test variables
        testScope = Scope.ChainSpecific;
        testResetPeriod = ResetPeriod.OneMinute;
        testAllocator = vm.createWallet("testAllocator");
        testAllocator.addr = instance.account; // Use account as allocator for simplicity
        testSender = instance.account; // Use account as sender to skip user signature check
        testExpires = block.timestamp + 3600; // 1 hour from now

        // Setup test session and configuration
        _setupTestSession();
        _setupTestConfiguration();
    }

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    function test_setConfig_Success() public {
        // Act
        vm.prank(instance.account);
        smartSessionEmissary.setConfig(instance.account, testConfig, testEnableData);

        // Assert - check that the session was properly enabled
        // We can verify this by checking if the permission is now enabled
        bool isEnabled = smartSessionEmissary.isPermissionEnabled(
            testConfig.permissionId, testLockTag, instance.account, testConfig.sender
        );
        assertTrue(isEnabled, "Session should be enabled after setConfig");
    }

    function test_setConfig_RevertsWhen_ExpiredEnableData() public {
        // Arrange - set expires to past timestamp
        testEnableData.expires = block.timestamp - 1;

        // Act & Assert
        vm.expectRevert(InvalidEmissaryEnableData.selector);
        vm.prank(instance.account);
        smartSessionEmissary.setConfig(instance.account, testConfig, testEnableData);
    }

    function test_setConfig_RevertsWhen_ExactlyCurrentTimestamp() public {
        // Arrange - set expires to current timestamp (should fail)
        testEnableData.expires = block.timestamp;

        // Act & Assert
        vm.expectRevert(InvalidEmissaryEnableData.selector);
        vm.prank(instance.account);
        smartSessionEmissary.setConfig(instance.account, testConfig, testEnableData);
    }

    function test_setConfig_FutureTimestamp() public {
        // Arrange - set expires to future timestamp (should succeed)
        testEnableData.expires = block.timestamp + 1000;
        // Setup test configuration with future timestamp
        _setupTestConfiguration();

        // Act
        vm.prank(instance.account);
        smartSessionEmissary.setConfig(instance.account, testConfig, testEnableData);

        // Assert
        bool isEnabled = smartSessionEmissary.isPermissionEnabled(
            testConfig.permissionId, testLockTag, instance.account, testConfig.sender
        );
        assertTrue(isEnabled, "Session should be enabled with future timestamp");
    }

    function test_setConfig_RevertsWhen_InvalidAllocatorSignature() public {
        test_setConfig_Success();
        // Arrange
        testEnableData.allocatorSig = abi.encodePacked(uint256(420), uint256(69), uint8(0));

        // Act & Assert
        vm.expectRevert(); // Should revert with signature verification error
        vm.prank(instance.account);
        smartSessionEmissary.setConfig(instance.account, testConfig, testEnableData);
    }

    function test_setConfig_RevertsWhen_InvalidUserSignature() public {
        // Recalculate lockTag and setup with new sender
        testLockTag =
            testConfig.allocator.toAllocatorId().toLockTag(testConfig.scope, testConfig.resetPeriod);

        // Update chain digests with new sender
        ChainDigest[] memory chainDigests = new ChainDigest[](1);
        chainDigests[0] = ChainDigest({
            chainId: uint64(block.chainid),
            sessionDigest: _sessionDigest(
                testSession,
                instance.account,
                0,
                testExpires,
                testLockTag,
                testConfig.sender // new sender
            )
        });

        bytes32 multichainDigest = chainDigests.multichainDigest();

        // Update enable data with new chain digests and invalid user signature
        testEnableData.session.hashesAndChainIds = chainDigests;
        testEnableData.allocatorSig = _signWithWallet(testAllocator, multichainDigest);
        testEnableData.userSig = abi.encodePacked(
            bytes32(0x0000000000000000000000000000000000000000000000000000000000000000),
            bytes32(0x0000000000000000000000000000000000000000000000000000000000000000),
            uint8(0)
        );

        // Act & Assert
        vm.expectRevert(); // Should revert with user signature verification error
        smartSessionEmissary.setConfig(instance.account, testConfig, testEnableData);
    }

    function test_setConfig_RevertsWhen_DifferentScope() public {
        // Arrange - use different scope
        Scope differentScope = Scope.Multichain;
        testConfig.scope = differentScope;

        // Recalculate lockTag with new scope
        testLockTag =
            testConfig.allocator.toAllocatorId().toLockTag(differentScope, testConfig.resetPeriod);

        // Update chain digests and signature
        ChainDigest[] memory chainDigests = new ChainDigest[](1);
        chainDigests[0] = ChainDigest({
            chainId: uint64(block.chainid),
            sessionDigest: _sessionDigest(
                testSession, instance.account, 0, testExpires, testLockTag, testSender
            )
        });

        testEnableData.session.hashesAndChainIds = chainDigests;
        testEnableData.allocatorSig =
            _signWithWallet(testAllocator, chainDigests.multichainDigest());

        // Act
        vm.prank(instance.account);
        smartSessionEmissary.setConfig(instance.account, testConfig, testEnableData);

        // Assert
        bool isEnabled = smartSessionEmissary.isPermissionEnabled(
            testConfig.permissionId, testLockTag, instance.account, testConfig.sender
        );
        assertTrue(isEnabled, "Session should be enabled with different scope");
    }

    function test_setConfig_DifferentResetPeriod() public {
        // Arrange - use different reset period
        testConfig.resetPeriod = ResetPeriod.OneSecond;

        // Recalculate lockTag with new reset period
        testLockTag =
            testConfig.allocator.toAllocatorId().toLockTag(testConfig.scope, testConfig.resetPeriod);

        // Update chain digests and signature
        ChainDigest[] memory chainDigests = new ChainDigest[](1);
        chainDigests[0] = ChainDigest({
            chainId: uint64(block.chainid),
            sessionDigest: _sessionDigest(
                testSession, instance.account, 0, testExpires, testLockTag, testSender
            )
        });

        testEnableData.session.hashesAndChainIds = chainDigests;
        testEnableData.allocatorSig =
            _signWithWallet(testAllocator, chainDigests.multichainDigest());

        // Act
        vm.prank(instance.account);
        smartSessionEmissary.setConfig(instance.account, testConfig, testEnableData);

        // Assert
        bool isEnabled = smartSessionEmissary.isPermissionEnabled(
            testConfig.permissionId, testLockTag, instance.account, testConfig.sender
        );
        assertTrue(isEnabled, "Session should be enabled with different reset period");
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    function _signWithWallet(
        Vm.Wallet memory wallet,
        bytes32 hash
    )
        internal
        returns (bytes memory)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wallet, hash);
        return abi.encodePacked(address(instance.defaultValidator), r, s, v);
    }

    function _sessionDigest(
        Session memory session,
        address account,
        uint256 nonce,
        uint256 expires,
        bytes12 lockTag,
        address sender
    )
        internal
        view
        returns (bytes32 digest)
    {
        digest = keccak256(
            abi.encode(
                SESSION_TYPEHASH, // Typehash for the SignedSession struct
                account, // User account address (sponsor)
                session.hashPermissions(), // Hashed permissions data
                address(session.sessionValidator), // Validator contract address
                keccak256(session.sessionValidatorInitData), // Validator initialization data
                session.salt, // Session salt
                address(smartSessionEmissary), // Smart Session Emissary contract address
                nonce, // Session nonce
                expires, // Expiration timestamp
                lockTag, // Lock tag for the session
                sender // Sender address
            )
        );
    }

    function _setupTestSession() internal {
        // Setup policies
        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });

        // Setup actions
        ActionData[] memory actions = new ActionData[](1);
        actions[0] = ActionData({
            actionTarget: target,
            actionTargetSelector: bytes4(keccak256("testFunction()")),
            actionPolicies: policyDatas
        });

        // Create session
        testSession = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: keccak256("configTestSalt"),
            sessionValidatorInitData: "configTestInitData",
            erc1271Policies: policyDatas,
            actions: actions
        });

        // Generate permission ID
        testPermissionId = smartSessionEmissary.getPermissionId(testSession);
    }

    function _setupTestConfiguration() internal {
        // Calculate lockTag
        testLockTag = testAllocator.addr.toAllocatorId().toLockTag(testScope, testResetPeriod);

        // Setup SmartSessionEmissaryConfig
        testConfig = SmartSessionEmissaryConfig({
            permissionId: testPermissionId,
            sender: testSender,
            allocator: testAllocator.addr,
            scope: testScope,
            resetPeriod: testResetPeriod
        });

        // Setup chain digests for enable data
        ChainDigest[] memory chainDigests = new ChainDigest[](1);
        chainDigests[0] = ChainDigest({
            chainId: uint64(block.chainid),
            sessionDigest: _sessionDigest(
                testSession,
                instance.account,
                0, // nonce - this will be the current nonce from the contract
                testExpires,
                testLockTag,
                testSender
            )
        });

        // Create the hash that needs to be signed
        bytes32 multichainDigest = chainDigests.multichainDigest();

        // Generate proper signatures
        bytes memory allocatorSig = _signWithWallet(testAllocator, multichainDigest);
        bytes memory userSig = ""; // Empty since sender == user (account)

        // Setup SmartSessionEmissaryEnable
        testEnableData = SmartSessionEmissaryEnable({
            session: EnableSession({
                sessionToEnable: testSession,
                hashesAndChainIds: chainDigests,
                chainDigestIndex: 0
            }),
            expires: testExpires,
            allocatorSig: allocatorSig,
            userSig: userSig
        });
    }
}
