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
import { PolicyData, ActionData, PermissionId } from "@smartsessions/DataTypes.sol";
import { Session } from "@types/DataTypes.sol";
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
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    function test_verifyClaim_SmartSessionMode_Success() public withEnabledClaimSession {
        // Arrange
        bytes memory emissaryData = packClaimData(EMISSARY_SMART_SESSION, mockSignature);

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
        bytes memory emissaryData = packClaimData(EMISSARY_SMART_SESSION, mockSignature);

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
