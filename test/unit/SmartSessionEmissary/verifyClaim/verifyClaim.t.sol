// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { SmartSessionEmissary_Unit_Test } from
    "@test/unit/SmartSessionEmissary/SmartSessionEmissary.t.sol";

// Interfaces
import { ISmartSessionEmissary } from "@interfaces/ISmartSessionEmissary.sol";
import { ISessionValidator } from "@smartsessions/interfaces/ISessionValidator.sol";
import { IStatelessValidator } from "@compact-utils/interfaces/IStatelessValidator.sol";

// Libraries
import { HashLib } from "@smartsessions/lib/HashLib.sol";
import { ModuleKitHelpers } from "@modulekit/ModuleKit.sol";
import { LibZip } from "solady/utils/LibZip.sol";

// Types
import { PolicyData, ActionData, PermissionId } from "@smartsessions/DataTypes.sol";
import { Session } from "@types/DataTypes.sol";
import {
    EmissaryMode,
    EMISSARY_SMART_SESSION,
    EMISSARY_ECDSA,
    EMISSARY_PASSKEY,
    EMISSARY_STATELESS_VALIDATOR
} from "@lib/ModeLib.sol";
import { Execution } from "@smartsessions/lib/ExecutionLib.sol";

contract SmartSessionEmissary_verifyClaim_Test is SmartSessionEmissary_Unit_Test {
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
    bytes12 testLockTag;
    bytes32 testClaimHash;
    bytes32 testDigest;
    string constant TEST_CONTENT = "TestContent(string data)";
    bytes mockSignature;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        // Call the base setup function.
        super.setUp();

        // Initialize test variables
        testClaimHash = keccak256("testClaim");
        testDigest = keccak256("testDigest");
        testLockTag = bytes12(keccak256("testLockTag"));

        // Deploy the account instance
        instance.deployAccount();
    }

    /*//////////////////////////////////////////////////////////////
                               STATELESS
    //////////////////////////////////////////////////////////////*/

    function test_verifyClaim_StatelessValidator_Success() public {
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
        bytes4 result = smartSessionEmissary.verifyClaim(
            instance.account, testDigest, testClaimHash, data, testLockTag
        );

        // Assert
        assertEq(
            result,
            ISmartSessionEmissary.verifyClaim.selector,
            "Should return successful verifyClaim selector"
        );
    }

    function test_verifyClaim_StatelessValidator_InvalidSignature() public {
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
        bytes4 result = smartSessionEmissary.verifyClaim(
            instance.account, testDigest, testClaimHash, data, testLockTag
        );

        // Assert
        assertEq(result, bytes4(0xFFFFFFFF), "Should return failure for invalid signature");
    }

    function test_verifyClaim_StatelessValidator_NoConfig() public {
        // Arrange
        address validator = address(yesSessionValidator);
        uint8 configId = 99; // Non-existent config
        bytes memory validatorSig = hex"abcdef";

        bytes memory data =
            abi.encodePacked(EMISSARY_STATELESS_VALIDATOR, validator, configId, validatorSig);

        // Act & Assert
        vm.expectRevert(ISmartSessionEmissary.InvalidEmissaryConfig.selector);
        smartSessionEmissary.verifyClaim(
            instance.account, testDigest, testClaimHash, data, testLockTag
        );
    }

    /*//////////////////////////////////////////////////////////////
                                 ECDSA
    //////////////////////////////////////////////////////////////*/

    function test_verifyClaim_ECDSA_Success() public {
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
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, testDigest);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes memory data = abi.encodePacked(EMISSARY_ECDSA, configId, signature);

        // Act
        bytes4 result = smartSessionEmissary.verifyClaim(
            instance.account, testDigest, testClaimHash, data, testLockTag
        );

        // Assert
        assertEq(
            result,
            ISmartSessionEmissary.verifyClaim.selector,
            "Should return successful verifyClaim selector"
        );
    }

    function test_verifyClaim_ECDSA_InvalidSignature() public {
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
        bytes4 result = smartSessionEmissary.verifyClaim(
            instance.account, testDigest, testClaimHash, data, testLockTag
        );

        // Assert
        assertEq(result, bytes4(0xFFFFFFFF), "Should return failure for wrong signature");
    }

    function test_verifyClaim_ECDSA_ThresholdNotMet() public {
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
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, testDigest);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes memory data = abi.encodePacked(EMISSARY_ECDSA, configId, signature);

        // Act
        bytes4 result = smartSessionEmissary.verifyClaim(
            instance.account, testDigest, testClaimHash, data, testLockTag
        );

        // Assert
        assertEq(result, bytes4(0xFFFFFFFF), "Should return failure when threshold not met");
    }

    function test_verifyClaim_ECDSA_NoConfig() public {
        // Arrange
        uint8 configId = 99; // Non-existent config
        bytes memory signature = hex"1234567890";

        bytes memory data = abi.encodePacked(EMISSARY_ECDSA, configId, signature);

        // Act & Assert
        vm.expectRevert(ISmartSessionEmissary.InvalidEmissaryConfig.selector);
        smartSessionEmissary.verifyClaim(
            instance.account, testDigest, testClaimHash, data, testLockTag
        );
    }

    /*//////////////////////////////////////////////////////////////
                                PASSKEY
    //////////////////////////////////////////////////////////////*/

    function test_verifyClaim_Passkey_NoConfig() public {
        // Arrange
        uint8 configId = 99; // Non-existent config
        bytes memory passkeySignature = hex"fedcba";

        bytes memory data = abi.encodePacked(EMISSARY_PASSKEY, configId, passkeySignature);

        // Act & Assert
        vm.expectRevert(ISmartSessionEmissary.InvalidEmissaryConfig.selector);
        smartSessionEmissary.verifyClaim(
            instance.account, testDigest, testClaimHash, data, testLockTag
        );
    }

    /*//////////////////////////////////////////////////////////////
                              SMART SESSION
    //////////////////////////////////////////////////////////////*/

    function test_verifyClaim_SmartSession_Success() public withEnabledClaimSession {
        // Arrange
        bytes memory emissaryData = packClaimData(EMISSARY_SMART_SESSION, mockSignature);

        // Act
        bytes4 result = smartSessionEmissary.verifyClaim(
            instance.account, testDigest, testClaimHash, emissaryData, testLockTag
        );

        // Assert
        assertEq(
            result,
            ISmartSessionEmissary.verifyClaim.selector,
            "Should return successful verifyClaim selector"
        );
    }

    function test_verifyClaim_SmartSession_InvalidSignature()
        public
        withEnabledClaimSessionWithFailingValidator
    {
        // Arrange
        bytes memory emissaryData = packClaimData(EMISSARY_SMART_SESSION, mockSignature);

        // Act
        bytes4 result = smartSessionEmissary.verifyClaim(
            instance.account, testDigest, testClaimHash, emissaryData, testLockTag
        );

        // Assert
        assertEq(result, bytes4(0xffffffff), "Should return failure code for invalid signature");
    }

    /*//////////////////////////////////////////////////////////////
                                  EDGE
    //////////////////////////////////////////////////////////////*/

    function test_verifyClaim_RevertsWhen_UnsupportedMode() public view {
        // Arrange
        EmissaryMode unsupportedMode = EmissaryMode.wrap(0xFF); // Invalid mode
        bytes memory emissaryData = abi.encodePacked(unsupportedMode, "mockData");

        // Act
        bytes4 result = smartSessionEmissary.verifyClaim(
            instance.account, testDigest, testClaimHash, emissaryData, testLockTag
        );

        // Assert
        assertEq(result, bytes4(0xffffffff), "Should return failure code for unsupported mode");
    }

    function test_verifyClaim_RevertsWhen_EmptyEmissaryData() public {
        // Arrange
        bytes memory emptyData = "";

        // Act & Assert
        vm.expectRevert();
        smartSessionEmissary.verifyClaim(
            instance.account, testDigest, testClaimHash, emptyData, testLockTag
        );
    }

    function test_verifyClaim_SmartSessionMode_RevertsWhen_MalformedSignature()
        public
        withEnabledClaimSession
    {
        // Arrange - Create malformed signature (too short)
        bytes memory malformedSignature = abi.encodePacked("shortSig");
        bytes memory emissaryData = packClaimData(EMISSARY_SMART_SESSION, malformedSignature);

        // Act
        vm.expectRevert();
        smartSessionEmissary.verifyClaim(
            instance.account, testDigest, testClaimHash, emissaryData, testLockTag
        );
    }

    /*//////////////////////////////////////////////////////////////
                                 CACHE
    //////////////////////////////////////////////////////////////*/

    function test_verifyClaim_CacheReadFromExecution() public {
        // Arrange - Setup ECDSA config
        uint8 configId = 1;
        uint256 privateKey = 0x1234567890123456789012345678901234567890123456789012345678901234;
        address signer = vm.addr(privateKey);

        address[] memory owners = new address[](1);
        owners[0] = signer;

        smartSessionEmissary.setupECDSAConfig(instance.account, configId, testLockTag, 1, owners);

        // Create signature
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, testDigest);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory data = abi.encodePacked(EMISSARY_ECDSA, configId, signature);

        // Create execution data
        bytes memory callData = abi.encodeWithSelector(bytes4(keccak256("testFunction()")));
        Execution[] memory executions = new Execution[](1);
        executions[0] = Execution({ target: target, value: value, callData: callData });

        // First call verifyExecution to populate cache
        bytes4 execResult = smartSessionEmissary.verifyExecution(
            instance.account, testDigest, data, executions, testLockTag
        );
        assertEq(execResult, ISmartSessionEmissary.verifyExecution.selector);

        // Check cache was populated by execution
        assertTrue(
            smartSessionEmissary.isDigestCachedECDSA(
                instance.account, testDigest, configId, testLockTag
            ),
            "Digest should be cached after execution"
        );

        // Now call verifyClaim with invalid signature - should succeed due to cache
        bytes memory wrongSig = abi.encodePacked(r, s, uint8(v + 1)); // Invalid v value
        bytes memory wrongData = abi.encodePacked(EMISSARY_ECDSA, configId, wrongSig);

        bytes4 claimResult = smartSessionEmissary.verifyClaim(
            instance.account, testDigest, testClaimHash, wrongData, testLockTag
        );

        // Should succeed from cache even with wrong signature
        assertEq(
            claimResult,
            ISmartSessionEmissary.verifyClaim.selector,
            "Should succeed from cache populated by execution"
        );
    }

    function test_verifyClaim_PreCachedDigest() public {
        // Arrange - set up config
        uint8 configId = 1;
        address[] memory owners = new address[](1);
        owners[0] = address(0x1234);

        smartSessionEmissary.setupECDSAConfig(instance.account, configId, testLockTag, 1, owners);

        // Pre-cache the digest without actually validating;
        smartSessionEmissary.setDigestCacheECDSA(
            instance.account, testDigest, configId, testLockTag
        );

        // Create data with invalid signature (should pass due to cache)
        bytes memory invalidSig = hex"deadbeef";
        bytes memory data = abi.encodePacked(EMISSARY_ECDSA, configId, invalidSig);

        // Act - should succeed even with invalid signature due to cache
        bytes4 result = smartSessionEmissary.verifyClaim(
            instance.account, testDigest, testClaimHash, data, testLockTag
        );

        // Assert
        assertEq(
            result,
            ISmartSessionEmissary.verifyClaim.selector,
            "Should succeed from pre-cached digest even with invalid signature"
        );
    }

    function test_verifyClaim_CacheHit_StatelessValidator() public {
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

        // Pre-populate cache directly
        smartSessionEmissary.setDigestCacheStateless(
            instance.account, testDigest, validator, configId, testLockTag
        );

        // Mock validator to fail - cache should still make it succeed
        vm.mockCall(
            validator,
            abi.encodeWithSelector(IStatelessValidator.validateSignatureWithData.selector),
            abi.encode(false)
        );

        // Verify claim should succeed from cache
        bytes4 result = smartSessionEmissary.verifyClaim(
            instance.account, testDigest, testClaimHash, data, testLockTag
        );

        assertEq(
            result,
            ISmartSessionEmissary.verifyClaim.selector,
            "Should succeed from cache even with mocked failure"
        );
    }

    function test_verifyClaim_CacheHit_ECDSA() public {
        // Arrange
        uint8 configId = 1;
        address[] memory owners = new address[](1);
        owners[0] = address(0x1234); // Any address, doesn't matter since we're using cache

        smartSessionEmissary.setupECDSAConfig(instance.account, configId, testLockTag, 1, owners);

        // Pre-populate cache directly
        smartSessionEmissary.setDigestCacheECDSA(
            instance.account, testDigest, configId, testLockTag
        );

        // Use completely invalid signature - should still succeed due to cache
        bytes memory invalidSig = hex"deadbeef";
        bytes memory data = abi.encodePacked(EMISSARY_ECDSA, configId, invalidSig);

        bytes4 result = smartSessionEmissary.verifyClaim(
            instance.account, testDigest, testClaimHash, data, testLockTag
        );

        assertEq(
            result,
            ISmartSessionEmissary.verifyClaim.selector,
            "Should succeed from cache even with invalid signature"
        );
    }

    function test_verifyClaim_CacheHit_SmartSession() public withEnabledClaimSession {
        // Arrange
        bytes memory emissaryData = packClaimData(EMISSARY_SMART_SESSION, mockSignature);

        // Pre-populate cache directly
        smartSessionEmissary.setDigestCacheSmartSession(
            instance.account, testDigest, testPermissionId, testLockTag
        );

        // Mock validator to fail - cache should still make it succeed
        vm.mockCall(
            address(yesSessionValidator),
            abi.encodeWithSelector(ISessionValidator.validateSignatureWithData.selector),
            abi.encode(false)
        );

        // Verify claim should succeed from cache
        bytes4 result = smartSessionEmissary.verifyClaim(
            instance.account, testDigest, testClaimHash, emissaryData, testLockTag
        );

        assertEq(
            result,
            ISmartSessionEmissary.verifyClaim.selector,
            "Should succeed from cache even with mocked failure"
        );
    }

    function test_verifyClaim_NoCacheForDifferentDigest() public {
        // Arrange
        uint8 configId = 1;
        address[] memory owners = new address[](1);
        owners[0] = address(0x1234);

        smartSessionEmissary.setupECDSAConfig(instance.account, configId, testLockTag, 1, owners);

        bytes32 digest1 = keccak256("digest1");
        bytes32 digest2 = keccak256("digest2");

        // Pre-populate cache for digest1 only
        smartSessionEmissary.setDigestCacheECDSA(instance.account, digest1, configId, testLockTag);

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
            "Second digest should not be cached"
        );

        // Try to verify second digest with invalid signature - should fail
        bytes memory invalidSig = hex"deadbeef";
        bytes memory data = abi.encodePacked(EMISSARY_ECDSA, configId, invalidSig);

        bytes4 result = smartSessionEmissary.verifyClaim(
            instance.account, digest2, testClaimHash, data, testLockTag
        );

        assertEq(result, bytes4(0xFFFFFFFF), "Should fail for uncached digest with invalid sig");
    }

    function test_verifyClaim_NoCacheForDifferentConfigId() public {
        // Arrange
        uint8 configId1 = 1;
        uint8 configId2 = 2;
        address[] memory owners = new address[](1);
        owners[0] = address(0x1234);

        // Setup both configs
        smartSessionEmissary.setupECDSAConfig(instance.account, configId1, testLockTag, 1, owners);
        smartSessionEmissary.setupECDSAConfig(instance.account, configId2, testLockTag, 1, owners);

        // Pre-populate cache for config1 only
        smartSessionEmissary.setDigestCacheECDSA(
            instance.account, testDigest, configId1, testLockTag
        );

        // Check cache for config1
        assertTrue(
            smartSessionEmissary.isDigestCachedECDSA(
                instance.account, testDigest, configId1, testLockTag
            ),
            "Should be cached for config1"
        );

        // Check cache for config2 (should not be cached)
        assertFalse(
            smartSessionEmissary.isDigestCachedECDSA(
                instance.account, testDigest, configId2, testLockTag
            ),
            "Should not be cached for config2"
        );

        // Try to verify with config2 and invalid signature - should fail
        bytes memory invalidSig = hex"deadbeef";
        bytes memory data = abi.encodePacked(EMISSARY_ECDSA, configId2, invalidSig);

        bytes4 result = smartSessionEmissary.verifyClaim(
            instance.account, testDigest, testClaimHash, data, testLockTag
        );

        assertEq(result, bytes4(0xFFFFFFFF), "Should fail for uncached config with invalid sig");
    }

    /*//////////////////////////////////////////////////////////////
                               MODIFIERS
    //////////////////////////////////////////////////////////////*/

    modifier withEnabledClaimSession() {
        // Prank to account
        vm.prank(instance.account);

        // Setup policies
        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });

        // Setup session
        Session memory session = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: keccak256("claimSalt"),
            sessionValidatorInitData: "mockInitData",
            erc1271Policies: policyDatas,
            actions: new ActionData[](0)
        });

        // Enable session
        Session[] memory sessions = new Session[](1);
        sessions[0] = session;

        // Set a mock lockTag for testing
        testLockTag = bytes12(keccak256("mockLockTag"));

        smartSessionEmissary.enableSessions(sessions, testLockTag, address(this));

        // Generate the permission ID
        testPermissionId = smartSessionEmissary.getPermissionId(session);

        //_ Create mock signature
        _createMockSignature();

        // Continue with the test
        _;
    }

    modifier withEnabledClaimSessionWithFailingValidator() {
        // Prank to account
        vm.prank(instance.account);

        // Setup  policies
        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });

        // Setup session with failing validator
        Session memory session = Session({
            sessionValidator: ISessionValidator(address(noSessionValidator)),
            salt: keccak256("failingClaimSalt"),
            sessionValidatorInitData: "mockInitData",
            erc1271Policies: policyDatas,
            actions: new ActionData[](0)
        });

        // Set a mock lockTag for testing
        testLockTag = bytes12(keccak256("mockLockTag"));

        // Enable session
        Session[] memory sessions = new Session[](1);
        sessions[0] = session;
        PermissionId[] memory testPermissionIds =
            smartSessionEmissary.enableSessions(sessions, testLockTag, address(this));
        testPermissionId = testPermissionIds[0];

        //_ Create mock signature
        _createMockSignature();

        // Continue with the test
        _;
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    function packClaimData(
        EmissaryMode emissaryMode,
        bytes memory signatureData
    )
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(emissaryMode, signatureData);
    }

    function _createMockSignature() internal {
        // Create mock signature components (r, s, v)
        bytes32 r = bytes32(0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef);
        bytes32 s = bytes32(0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321);
        uint8 v = 27;

        // Create contents and contentsDescription
        bytes32 contents = keccak256(abi.encode("testData", TEST_CONTENT));

        // Construct the signature
        bytes memory sessionSignature = abi.encodePacked(
            r,
            s,
            v, // Session validator signature
            contents // Contents hash
        );

        // Prepend the permissionId
        mockSignature =
            abi.encodePacked(testPermissionId, sessionSignature.length + 64, sessionSignature);
    }
}
