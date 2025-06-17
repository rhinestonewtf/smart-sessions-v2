// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { SmartSessionEmissary_Unit_Test } from
    "@test/unit/SmartSessionEmissary/SmartSessionEmissary.t.sol";

// Interfaces
import { ISmartSessionEmissary } from "@interfaces/ISmartSessionEmissary.sol";
import { ISessionValidator } from "@smartsessions/interfaces/ISessionValidator.sol";

// Libraries
import { HashLib } from "@smartsessions/lib/HashLib.sol";
import { ModuleKitHelpers } from "@modulekit/ModuleKit.sol";
import { LibZip } from "solady/utils/LibZip.sol";

// Types
import {
    Session,
    PolicyData,
    ActionData,
    PermissionId,
    ERC7739Data,
    ERC7739Context
} from "@smartsessions/DataTypes.sol";
import { EmissaryMode, EMISSARY_SMART_SESSION } from "@lib/ModeLib.sol";

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
    bytes32 appDomainSeparator;
    string constant TEST_CONTENT = "TestContent(string data)";
    string constant TEST_CONTENT_NAME = "TestContent";
    bytes mockERC7739Signature;

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

        // Setup app domain separator (mimicking an external app)
        appDomainSeparator = keccak256(
            abi.encodePacked(
                "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
                keccak256("TestApp"),
                keccak256("1"),
                block.chainid,
                address(0x1234567890123456789012345678901234567890)
            )
        );

        // Deploy the account instance
        instance.deployAccount();
    }

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    function test_verifyClaim_ERC7739SupportDetection() public view {
        // Arrange
        bytes32 erc7739DetectionHash =
            0x7739773977397739773977397739773977397739773977397739773977397739;
        bytes memory emptyData = "";

        // Act
        bytes4 result = smartSessionEmissary.verifyClaim(
            instance.account, erc7739DetectionHash, bytes32(0), emptyData, testLockTag
        );

        // Assert
        assertEq(result, bytes4(0x77390001), "Should return ERC-7739 support indicator");
    }

    function test_verifyClaim_SmartSessionMode_Success() public withEnabledClaimSession {
        // Arrange
        bytes memory emissaryData = packClaimData(EMISSARY_SMART_SESSION, mockERC7739Signature);

        // Act
        bytes4 result = smartSessionEmissary.verifyClaim(
            instance.account, testDigest, testClaimHash, emissaryData, testLockTag
        );

        // Assert
        assertEq(
            result,
            bytes4(keccak256("verifyClaim(address,bytes32,bytes32,bytes,bytes12)")),
            "Should return successful verifyClaim selector"
        );
    }

    function test_verifyClaim_SmartSessionMode_InvalidSignature()
        public
        withEnabledClaimSessionWithFailingValidator
    {
        // Arrange
        bytes memory emissaryData = packClaimData(EMISSARY_SMART_SESSION, mockERC7739Signature);

        // Act
        bytes4 result = smartSessionEmissary.verifyClaim(
            instance.account, testDigest, testClaimHash, emissaryData, testLockTag
        );

        // Assert
        assertEq(result, bytes4(0xffffffff), "Should return failure code for invalid signature");
    }

    function test_verifyClaim_UnsupportedMode() public view {
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

    function test_verifyClaim_EmptyEmissaryData() public {
        // Arrange
        bytes memory emptyData = "";

        // Act & Assert
        vm.expectRevert();
        smartSessionEmissary.verifyClaim(
            instance.account, testDigest, testClaimHash, emptyData, testLockTag
        );
    }

    function test_verifyClaim_SmartSessionMode_MalformedSignature()
        public
        withEnabledClaimSession
    {
        // Arrange - Create malformed ERC-7739 signature (too short)
        bytes memory malformedSignature = abi.encodePacked(testPermissionId, "shortSig");
        bytes memory emissaryData = packClaimData(EMISSARY_SMART_SESSION, malformedSignature);

        // Act
        vm.expectRevert();
        smartSessionEmissary.verifyClaim(
            instance.account, testDigest, testClaimHash, emissaryData, testLockTag
        );
    }

    /*//////////////////////////////////////////////////////////////
                               MODIFIERS
    //////////////////////////////////////////////////////////////*/

    modifier withEnabledClaimSession() {
        // Prank to account
        vm.prank(instance.account);

        // Setup ERC-7739 content policies
        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });

        // Create ERC-7739 data with the test content enabled
        ERC7739Data memory erc7739Data = ERC7739Data({
            allowedERC7739Content: _createAllowedContent(),
            erc1271Policies: policyDatas
        });

        // Setup session
        Session memory session = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: keccak256("claimSalt"),
            sessionValidatorInitData: "mockInitData",
            userOpPolicies: new PolicyData[](0),
            erc7739Policies: erc7739Data,
            actions: new ActionData[](0),
            permitERC4337Paymaster: false
        });

        // Enable session
        Session[] memory sessions = new Session[](1);
        sessions[0] = session;
        smartSessionEmissary.enableSessions(sessions);

        // Generate the permission ID
        testPermissionId = smartSessionEmissary.getPermissionId(session);

        // Set a mock lockTag for testing
        testLockTag = bytes12(keccak256("mockLockTag"));

        //_ Create mock ERC-7739 signature
        _createMockERC7739Signature();

        // Continue with the test
        _;
    }

    modifier withEnabledClaimSessionWithFailingValidator() {
        // Prank to account
        vm.prank(instance.account);

        // Setup ERC-7739 content policies
        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });

        // Create ERC-7739 data with the test content enabled
        ERC7739Data memory erc7739Data = ERC7739Data({
            allowedERC7739Content: _createAllowedContent(),
            erc1271Policies: policyDatas
        });

        // Setup session with failing validator
        Session memory session = Session({
            sessionValidator: ISessionValidator(address(noSessionValidator)),
            salt: keccak256("failingClaimSalt"),
            sessionValidatorInitData: "mockInitData",
            userOpPolicies: new PolicyData[](0),
            erc7739Policies: erc7739Data,
            actions: new ActionData[](0),
            permitERC4337Paymaster: false
        });

        // Enable session
        Session[] memory sessions = new Session[](1);
        sessions[0] = session;
        PermissionId[] memory testPermissionIds = smartSessionEmissary.enableSessions(sessions);
        testPermissionId = testPermissionIds[0];

        // Set a mock lockTag for testing
        testLockTag = bytes12(keccak256("mockLockTag"));

        //_ Create mock ERC-7739 signature
        _createMockERC7739Signature();

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

    function _createAllowedContent() internal view returns (ERC7739Context[] memory) {
        ERC7739Context[] memory contexts = new ERC7739Context[](1);
        string[] memory contentNames = new string[](1);
        contentNames[0] = string(abi.encodePacked(TEST_CONTENT, TEST_CONTENT_NAME));
        contexts[0] =
            ERC7739Context({ appDomainSeparator: appDomainSeparator, contentNames: contentNames });
        return contexts;
    }

    function _createMockERC7739Signature() internal {
        // Create mock signature components (r, s, v)
        bytes32 r = bytes32(0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef);
        bytes32 s = bytes32(0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321);
        uint8 v = 27;

        // Create contents and contentsDescription
        bytes32 contents = keccak256(abi.encode("testData", TEST_CONTENT));
        bytes memory contentsDescription = abi.encodePacked(TEST_CONTENT, TEST_CONTENT_NAME);

        // Construct the signature following ERC-7739 format
        bytes memory sessionSignature = abi.encodePacked(
            r,
            s,
            v, // Session validator signature
            appDomainSeparator, // App domain separator
            contents, // Contents hash
            contentsDescription, // Contents type + name
            uint16(contentsDescription.length) // Length of contents description
        );

        // Prepend the permissionId
        mockERC7739Signature = abi.encodePacked(testPermissionId, sessionSignature);
    }
}
