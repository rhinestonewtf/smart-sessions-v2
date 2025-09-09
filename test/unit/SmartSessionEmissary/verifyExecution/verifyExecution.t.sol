// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { SmartSessionEmissary_Unit_Test } from
    "@test/unit/SmartSessionEmissary/SmartSessionEmissary.t.sol";

// Interfaces
import { ISmartSessionEmissary } from "@interfaces/ISmartSessionEmissary.sol";
import { ISessionValidator } from "@smartsessions/interfaces/ISessionValidator.sol";
import { IERC7579Account } from "erc7579/interfaces/IERC7579Account.sol";
import { IStatelessValidator } from "@compact-utils/interfaces/IStatelessValidator.sol";

// Libraries
import { ExecutionLib, Execution } from "@smartsessions/lib/ExecutionLib.sol";
import { HashLib } from "@smartsessions/lib/HashLib.sol";
import { ModuleKitHelpers } from "@modulekit/ModuleKit.sol";
import { LibZip } from "solady/utils/LibZip.sol";
import { WebAuthn } from "@webauthn/WebAuthn.sol";

// Types
import {
    PolicyData,
    ActionData,
    FALLBACK_TARGET_FLAG,
    FALLBACK_TARGET_SELECTOR_FLAG,
    PermissionId,
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
import {
    EmissaryMode,
    EMISSARY_SMART_SESSION,
    EMISSARY_STATELESS_VALIDATOR,
    EMISSARY_ECDSA,
    EMISSARY_PASSKEY
} from "@lib/ModeLib.sol";
import { MODULE_TYPE_VALIDATOR } from "erc7579/interfaces/IERC7579Module.sol";
import { Session } from "@types/DataTypes.sol";

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
    Execution[] mockExecData;
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
        mockExecData = executions;

        // Setup testValidator as default validator
        testValidator = address(instance.defaultValidator);

        // Deploy the account instance
        instance.deployAccount();
    }

    /*//////////////////////////////////////////////////////////////
                               STATELESS
    //////////////////////////////////////////////////////////////*/

    function test_verifyExecution_StatelessValidator_Success() public {
        // Arrange
        address validator = address(yesSessionValidator);
        uint8 configId = 1;
        bytes memory validatorConfig = hex"1234";
        bytes memory validatorSig = hex"abcdef";

        // Setup stateless validator config
        smartSessionEmissary.setupStatelessValidatorConfig(
            instance.account, configId, testLockTag, IStatelessValidator(validator), validatorConfig
        );

        bytes memory data =
            abi.encodePacked(EMISSARY_STATELESS_VALIDATOR, validator, configId, validatorSig);

        // Act
        bytes4 result = smartSessionEmissary.verifyExecution(
            instance.account, TEST_HASH, data, mockExecData, testLockTag
        );

        // Assert
        assertEq(
            result,
            ISmartSessionEmissary.verifyExecution.selector,
            "Should return successful verification selector for stateless validator"
        );
    }

    function test_verifyExecution_StatelessValidator_RevertsWhen_InvalidSignature() public {
        // Arrange
        address validator = address(noSessionValidator);
        uint8 configId = 1;
        bytes memory validatorConfig = hex"1234";
        bytes memory validatorSig = hex"abcdef";

        // Setup stateless validator config
        smartSessionEmissary.setupStatelessValidatorConfig(
            instance.account, configId, testLockTag, IStatelessValidator(validator), validatorConfig
        );

        bytes memory data =
            abi.encodePacked(EMISSARY_STATELESS_VALIDATOR, validator, configId, validatorSig);

        // Act
        bytes4 result = smartSessionEmissary.verifyExecution(
            instance.account, TEST_HASH, data, mockExecData, testLockTag
        );

        // Assert
        assertEq(result, bytes4(0xFFFFFFFF), "Should return failure for invalid signature");
    }

    function test_verifyExecution_StatelessValidator_RevertsWhen_NoConfig() public {
        // Arrange
        address validator = address(yesSessionValidator);
        uint8 configId = 99; // Non-existent config
        bytes memory validatorSig = hex"abcdef";

        bytes memory data =
            abi.encodePacked(EMISSARY_STATELESS_VALIDATOR, validator, configId, validatorSig);

        // Act & Assert
        vm.expectRevert(ISmartSessionEmissary.InvalidEmissaryConfig.selector);
        smartSessionEmissary.verifyExecution(
            instance.account, TEST_HASH, data, mockExecData, testLockTag
        );
    }

    /*//////////////////////////////////////////////////////////////
                                 ECDSA
    //////////////////////////////////////////////////////////////*/

    function test_verifyExecution_ECDSA_Success() public {
        // Arrange
        uint8 configId = 1;
        uint256 privateKey = 0x1234567890123456789012345678901234567890123456789012345678901234;
        address signer = vm.addr(privateKey);

        // Setup ECDSA config with threshold and owners
        address[] memory owners = new address[](1);
        owners[0] = signer;
        uint256 threshold = 1;

        smartSessionEmissary.setupECDSAConfig(
            instance.account, configId, testLockTag, threshold, owners
        );

        // Create signature
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, TEST_HASH);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes memory data = abi.encodePacked(EMISSARY_ECDSA, configId, signature);

        // Act
        bytes4 result = smartSessionEmissary.verifyExecution(
            instance.account, TEST_HASH, data, mockExecData, testLockTag
        );

        // Assert
        assertEq(
            result,
            ISmartSessionEmissary.verifyExecution.selector,
            "Should return successful verification selector for ECDSA"
        );
    }

    function test_verifyExecution_ECDSA_RevertsWhen_InvalidSignature() public {
        // Arrange
        uint8 configId = 1;
        uint256 privateKey = 0x1234567890123456789012345678901234567890123456789012345678901234;
        address signer = vm.addr(privateKey);

        // Setup ECDSA config
        address[] memory owners = new address[](1);
        owners[0] = signer;
        uint256 threshold = 1;

        smartSessionEmissary.setupECDSAConfig(
            instance.account, configId, testLockTag, threshold, owners
        );

        // Create wrong signature (sign different hash)
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, keccak256("wrong"));
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes memory data = abi.encodePacked(EMISSARY_ECDSA, configId, signature);

        // Act
        bytes4 result = smartSessionEmissary.verifyExecution(
            instance.account, TEST_HASH, data, mockExecData, testLockTag
        );

        // Assert
        assertEq(result, bytes4(0xFFFFFFFF), "Should return failure for wrong signature");
    }

    function test_verifyExecution_ECDSA_RevertsWhen_ThresholdNotMet() public {
        // Arrange
        uint8 configId = 1;
        uint256 privateKey = 0x1234567890123456789012345678901234567890123456789012345678901234;
        address signer = vm.addr(privateKey);

        // Setup ECDSA config with threshold 2 but only 1 signer
        address[] memory owners = new address[](2);
        owners[0] = signer;
        owners[1] = address(0x9999);
        uint256 threshold = 2;

        smartSessionEmissary.setupECDSAConfig(
            instance.account, configId, testLockTag, threshold, owners
        );

        // Create signature from only one signer
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, TEST_HASH);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes memory data = abi.encodePacked(EMISSARY_ECDSA, configId, signature);

        // Act
        bytes4 result = smartSessionEmissary.verifyExecution(
            instance.account, TEST_HASH, data, mockExecData, testLockTag
        );

        // Assert
        assertEq(result, bytes4(0xFFFFFFFF), "Should return failure when threshold not met");
    }

    function test_verifyExecution_ECDSA_RevertsWhen_NoConfig() public {
        // Arrange
        uint8 configId = 99; // Non-existent config
        bytes memory signature = hex"1234567890";

        bytes memory data = abi.encodePacked(EMISSARY_ECDSA, configId, signature);

        // Act & Assert
        vm.expectRevert(ISmartSessionEmissary.InvalidEmissaryConfig.selector);
        smartSessionEmissary.verifyExecution(
            instance.account, TEST_HASH, data, mockExecData, testLockTag
        );
    }

    /*//////////////////////////////////////////////////////////////
                                PASSKEY
    //////////////////////////////////////////////////////////////*/

    function test_verifyExecution_Passkey_RevertsWhen_NoConfig() public {
        // Arrange
        uint8 configId = 99; // Non-existent config
        bytes memory passkeySignature = hex"fedcba";

        bytes memory data = abi.encodePacked(EMISSARY_PASSKEY, configId, passkeySignature);

        // Act & Assert
        vm.expectRevert(ISmartSessionEmissary.InvalidEmissaryConfig.selector);
        smartSessionEmissary.verifyExecution(
            instance.account, TEST_HASH, data, mockExecData, testLockTag
        );
    }

    /*//////////////////////////////////////////////////////////////
                             SMART SESSION
    //////////////////////////////////////////////////////////////*/

    function test_verifyExecution_SmartSession_Success() public withEnabledSudoSession {
        // Arrange
        bytes memory data = packData(EMISSARY_SMART_SESSION, testPermissionId, mockSignature);

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
            target: target,
            value: value,
            callData: abi.encodeWithSelector(mockTargetSelector)
        });

        executions[1] = Execution({
            target: address(0x123),
            value: 0,
            callData: abi.encodeWithSelector(bytes4(keccak256("anotherFunction()")))
        });

        // Act
        bytes4 result = smartSessionEmissary.verifyExecution(
            instance.account, TEST_HASH, data, executions, testLockTag
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

    function test_verifyExecution_CacheHit_StatelessValidator() public {
        // Arrange
        address validator = address(yesSessionValidator);
        uint8 configId = 1;
        bytes memory validatorConfig = hex"1234";
        bytes memory validatorSig = hex"abcdef";

        smartSessionEmissary.setupStatelessValidatorConfig(
            instance.account, configId, testLockTag, IStatelessValidator(validator), validatorConfig
        );

        bytes memory data =
            abi.encodePacked(EMISSARY_STATELESS_VALIDATOR, validator, configId, validatorSig);

        // First call - validates and caches
        bytes4 result1 = smartSessionEmissary.verifyExecution(
            instance.account, TEST_HASH, data, mockExecData, testLockTag
        );
        assertEq(result1, ISmartSessionEmissary.verifyExecution.selector);

        // Check cache was populated
        bool isCached = smartSessionEmissary.isDigestCachedStateless(
            instance.account, TEST_HASH, validator, configId, testLockTag
        );
        assertTrue(isCached, "Digest should be cached after first verification");

        // Second call - should hit cache (no validation called)
        // We can verify by mocking the validator to fail, but cache should still return success
        vm.mockCall(
            validator,
            abi.encodeWithSelector(IStatelessValidator.validateSignatureWithData.selector),
            abi.encode(false) // Mock to return false
        );

        bytes4 result2 = smartSessionEmissary.verifyExecution(
            instance.account, TEST_HASH, data, mockExecData, testLockTag
        );
        assertEq(
            result2,
            ISmartSessionEmissary.verifyExecution.selector,
            "Should succeed from cache even with mocked failure"
        );
    }

    function test_verifyExecution_CacheHit_ECDSA() public {
        // Arrange
        uint8 configId = 1;
        uint256 privateKey = 0x1234567890123456789012345678901234567890123456789012345678901234;
        address signer = vm.addr(privateKey);

        address[] memory owners = new address[](1);
        owners[0] = signer;

        smartSessionEmissary.setupECDSAConfig(instance.account, configId, testLockTag, 1, owners);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, TEST_HASH);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory data = abi.encodePacked(EMISSARY_ECDSA, configId, signature);

        // First call - validates and caches
        bytes4 result1 = smartSessionEmissary.verifyExecution(
            instance.account, TEST_HASH, data, mockExecData, testLockTag
        );
        assertEq(result1, ISmartSessionEmissary.verifyExecution.selector);

        // Check cache was populated
        bool isCached = smartSessionEmissary.isDigestCachedECDSA(
            instance.account, TEST_HASH, configId, testLockTag
        );
        assertTrue(isCached, "Digest should be cached after first verification");

        // Second call with invalid signature - should still succeed due to cache
        bytes memory wrongSig = abi.encodePacked(r, s, uint8(v + 1)); // Invalid v value
        bytes memory wrongData = abi.encodePacked(EMISSARY_ECDSA, configId, wrongSig);

        bytes4 result2 = smartSessionEmissary.verifyExecution(
            instance.account, TEST_HASH, wrongData, mockExecData, testLockTag
        );
        assertEq(
            result2,
            ISmartSessionEmissary.verifyExecution.selector,
            "Should succeed from cache even with wrong signature"
        );
    }

    function test_verifyExecution_CacheHit_SmartSession() public withEnabledSudoSession {
        // Arrange
        bytes memory data = packData(EMISSARY_SMART_SESSION, testPermissionId, mockSignature);

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

        // Second call - should hit cache
        bytes4 result2 = smartSessionEmissary.verifyExecution(
            instance.account, TEST_HASH, data, mockExecData, testLockTag
        );
        assertEq(result2, ISmartSessionEmissary.verifyExecution.selector);
    }

    function test_verifyExecution_NoCacheForDifferentDigest() public {
        // Arrange
        uint8 configId = 1;
        uint256 privateKey = 0x1234567890123456789012345678901234567890123456789012345678901234;
        address signer = vm.addr(privateKey);

        address[] memory owners = new address[](1);
        owners[0] = signer;

        smartSessionEmissary.setupECDSAConfig(instance.account, configId, testLockTag, 1, owners);

        // First digest
        bytes32 digest1 = keccak256("digest1");
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(privateKey, digest1);
        bytes memory sig1 = abi.encodePacked(r1, s1, v1);
        bytes memory data1 = abi.encodePacked(EMISSARY_ECDSA, configId, sig1);

        // Second digest
        bytes32 digest2 = keccak256("digest2");
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(privateKey, digest2);
        bytes memory sig2 = abi.encodePacked(r2, s2, v2);
        bytes memory data2 = abi.encodePacked(EMISSARY_ECDSA, configId, sig2);

        // Verify first digest
        bytes4 result1 = smartSessionEmissary.verifyExecution(
            instance.account, digest1, data1, mockExecData, testLockTag
        );
        assertEq(result1, ISmartSessionEmissary.verifyExecution.selector);

        // Check first digest is cached
        assertTrue(
            smartSessionEmissary.isDigestCachedECDSA(
                instance.account, digest1, configId, testLockTag
            ),
            "First digest should be cached"
        );

        // Check second digest is NOT cached
        assertFalse(
            smartSessionEmissary.isDigestCachedECDSA(
                instance.account, digest2, configId, testLockTag
            ),
            "Second digest should not be cached yet"
        );

        // Verify second digest (should not use cache)
        bytes4 result2 = smartSessionEmissary.verifyExecution(
            instance.account, digest2, data2, mockExecData, testLockTag
        );
        assertEq(result2, ISmartSessionEmissary.verifyExecution.selector);

        // Now both should be cached
        assertTrue(
            smartSessionEmissary.isDigestCachedECDSA(
                instance.account, digest1, configId, testLockTag
            ),
            "First digest should still be cached"
        );
        assertTrue(
            smartSessionEmissary.isDigestCachedECDSA(
                instance.account, digest2, configId, testLockTag
            ),
            "Second digest should now be cached"
        );
    }

    function test_verifyExecution_NoCacheForDifferentConfigId() public {
        // Arrange
        uint8 configId1 = 1;
        uint8 configId2 = 2;
        uint256 privateKey = 0x1234567890123456789012345678901234567890123456789012345678901234;
        address signer = vm.addr(privateKey);

        address[] memory owners = new address[](1);
        owners[0] = signer;

        // Setup both configs
        smartSessionEmissary.setupECDSAConfig(instance.account, configId1, testLockTag, 1, owners);
        smartSessionEmissary.setupECDSAConfig(instance.account, configId2, testLockTag, 1, owners);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, TEST_HASH);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes memory data1 = abi.encodePacked(EMISSARY_ECDSA, configId1, signature);
        bytes memory data2 = abi.encodePacked(EMISSARY_ECDSA, configId2, signature);

        // Verify with first config
        smartSessionEmissary.verifyExecution(
            instance.account, TEST_HASH, data1, mockExecData, testLockTag
        );

        // Check cache for config1
        assertTrue(
            smartSessionEmissary.isDigestCachedECDSA(
                instance.account, TEST_HASH, configId1, testLockTag
            ),
            "Config1 digest should be cached"
        );

        // Check cache for config2 (should not be cached)
        assertFalse(
            smartSessionEmissary.isDigestCachedECDSA(
                instance.account, TEST_HASH, configId2, testLockTag
            ),
            "Config2 digest should not be cached yet"
        );
    }

    function test_verifyExecution_CacheNotPopulatedOnFailure() public {
        // Arrange
        uint8 configId = 1;
        uint256 privateKey = 0x1234567890123456789012345678901234567890123456789012345678901234;
        address signer = vm.addr(privateKey);

        address[] memory owners = new address[](1);
        owners[0] = signer;

        smartSessionEmissary.setupECDSAConfig(instance.account, configId, testLockTag, 1, owners);

        // Sign wrong hash
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, keccak256("wrong"));
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory data = abi.encodePacked(EMISSARY_ECDSA, configId, signature);

        // Verify (should fail)
        bytes4 result = smartSessionEmissary.verifyExecution(
            instance.account, TEST_HASH, data, mockExecData, testLockTag
        );
        assertEq(result, bytes4(0xFFFFFFFF), "Should fail verification");

        // Check cache was NOT populated
        assertFalse(
            smartSessionEmissary.isDigestCachedECDSA(
                instance.account, TEST_HASH, configId, testLockTag
            ),
            "Digest should not be cached after failed verification"
        );
    }

    function test_verifyExecution_PreCachedDigest() public {
        // Arrange - set up config
        uint8 configId = 1;
        address[] memory owners = new address[](1);
        owners[0] = address(0x1234);

        smartSessionEmissary.setupECDSAConfig(instance.account, configId, testLockTag, 1, owners);

        // Pre-cache the digest without actually validating
        bytes32 cacheKey = keccak256(abi.encodePacked(configId, testLockTag));
        smartSessionEmissary.setDigestCacheECDSA(instance.account, TEST_HASH, configId, testLockTag);

        // Create data with invalid signature (should pass due to cache)
        bytes memory invalidSig = hex"deadbeef";
        bytes memory data = abi.encodePacked(EMISSARY_ECDSA, configId, invalidSig);

        // Act - should succeed even with invalid signature due to cache
        bytes4 result = smartSessionEmissary.verifyExecution(
            instance.account, TEST_HASH, data, mockExecData, testLockTag
        );

        // Assert
        assertEq(
            result,
            ISmartSessionEmissary.verifyExecution.selector,
            "Should succeed from pre-cached digest even with invalid signature"
        );
    }

    function test_verifyExecution_CacheClearedMidTransaction() public {
        // Arrange
        uint8 configId = 1;
        uint256 privateKey = 0x1234567890123456789012345678901234567890123456789012345678901234;
        address signer = vm.addr(privateKey);

        address[] memory owners = new address[](1);
        owners[0] = signer;
        smartSessionEmissary.setupECDSAConfig(instance.account, configId, testLockTag, 1, owners);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, TEST_HASH);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory data = abi.encodePacked(EMISSARY_ECDSA, configId, signature);

        // First verification - populates cache
        smartSessionEmissary.verifyExecution(
            instance.account, TEST_HASH, data, mockExecData, testLockTag
        );

        // Clear the cache
        smartSessionEmissary.clearDigestCacheECDSA(
            instance.account, TEST_HASH, configId, testLockTag
        );

        // Verify cache was cleared
        assertFalse(
            smartSessionEmissary.isDigestCachedECDSA(
                instance.account, TEST_HASH, configId, testLockTag
            ),
            "Cache should be cleared"
        );

        // Second verification - should need to validate again
        bytes4 result = smartSessionEmissary.verifyExecution(
            instance.account, TEST_HASH, data, mockExecData, testLockTag
        );

        assertEq(result, ISmartSessionEmissary.verifyExecution.selector);
        assertTrue(
            smartSessionEmissary.isDigestCachedECDSA(
                instance.account, TEST_HASH, configId, testLockTag
            ),
            "Cache should be repopulated after second verification"
        );
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
        // Act
        bytes4 result = smartSessionEmissary.verifyExecution(
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

        // Create erc1271

        // Setup session
        Session memory session = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: keccak256("salt"),
            sessionValidatorInitData: "mockInitData",
            erc1271Policies: new PolicyData[](0),
            actions: actions
        });

        // Enable session
        Session[] memory sessions = new Session[](1);
        sessions[0] = session;
        smartSessionEmissary.enableSessions(sessions, testLockTag, address(this));

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
            erc1271Policies: new PolicyData[](0),
            actions: actions
        });

        // Enable session
        Session[] memory sessions = new Session[](1);
        sessions[0] = session;
        smartSessionEmissary.enableSessions(sessions, testLockTag, address(this));

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
            erc1271Policies: new PolicyData[](0),
            actions: actions
        });

        // Enable session
        Session[] memory sessions = new Session[](1);
        sessions[0] = session;
        smartSessionEmissary.enableSessions(sessions, testLockTag, address(this));

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

        // Create a basic session
        session = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: keccak256("enableSalt"),
            sessionValidatorInitData: "mockInitData",
            erc1271Policies: new PolicyData[](0),
            actions: actions
        });

        // Calculate the permission ID
        testPermissionId = smartSessionEmissary.getPermissionId(session);
    }
}
