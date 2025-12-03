// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import {
    SmartSessionEmissary_Unit_Test
} from "@test/unit/SmartSessionEmissary/SmartSessionEmissary.t.sol";
import {
    SmartSessionCompatibilityFallback
} from "@smartsessions/SmartSessionCompatibilityFallback.sol";

// Interfaces
import { ISmartSessionEmissary } from "@interfaces/ISmartSessionEmissary.sol";
import { ISessionValidator } from "@smartsessions/interfaces/ISessionValidator.sol";
import { IERC1271, EIP1271_MAGIC_VALUE } from "@modulekit/module-bases/interfaces/IERC1271.sol";

// Libraries
import { HashLib } from "@smartsessions/lib/HashLib.sol";
import { ModuleKitHelpers } from "@modulekit/ModuleKit.sol";
import { LibString } from "solady/utils/LibString.sol";
import { EIP712 } from "solady/utils/EIP712.sol";
import { Solarray } from "solarray/Solarray.sol";

// Types
import {
    PolicyData,
    ActionData,
    PermissionId,
    ERC7739Data,
    ERC7739Context
} from "@smartsessions/DataTypes.sol";
import { Session } from "@types/DataTypes.sol";
import {
    MODULE_TYPE_FALLBACK,
    MODULE_TYPE_VALIDATOR
} from "@modulekit/accounts/common/interfaces/IERC7579Module.sol";
import { CALLTYPE_STATIC } from "erc7579/lib/ModeLib.sol";

contract SmartSessionEmissary_isValidSignatureWithSender_Test is SmartSessionEmissary_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using ModuleKitHelpers for *;
    using HashLib for *;

    /*//////////////////////////////////////////////////////////////
                                 STRUCTS
    //////////////////////////////////////////////////////////////*/

    struct TestTemps {
        address owner;
        uint256 chainId;
        bytes32 salt;
        address account;
        address signer;
        uint256 privateKey;
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    /*//////////////////////////////////////////////////////////////
                                 VARIABLES
    //////////////////////////////////////////////////////////////*/

    PermissionId testPermissionId;
    bytes32 testContentHash;
    bytes32 testMessageHash;
    bytes32 appDomainSeparator;
    string constant TEST_CONTENT_TYPE = "TestContent(string data)";
    string constant TEST_CONTENT_NAME = "TestContent";
    bytes mockSignature;
    Account sessionSigner;

    /*//////////////////////////////////////////////////////////////
                                 CONSTANTS
    //////////////////////////////////////////////////////////////*/

    bytes4 constant ERC1271_MAGIC_VALUE = 0x1626ba7e;
    bytes4 constant INVALID_SIGNATURE = 0xffffffff;
    bytes32 constant ERC7739_DETECTION_HASH =
        0x7739773977397739773977397739773977397739773977397739773977397739;
    bytes4 constant ERC7739_SUPPORT_VALUE = 0x77390001;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        // Call the base setup function
        super.setUp();

        // Deploy the account instance
        instance.deployAccount();

        // Install fallback to account
        bytes memory _fallback = abi.encode(EIP712.eip712Domain.selector, CALLTYPE_STATIC, "");
        instance.installModule({
            moduleTypeId: MODULE_TYPE_FALLBACK, module: address(fallbackModule), data: _fallback
        });

        // Install SmartSessionEmissary to account
        instance.installModule({
            moduleTypeId: MODULE_TYPE_VALIDATOR, module: address(smartSessionEmissary), data: ""
        });

        // Create session signer
        sessionSigner = makeAccount("sessionSigner");

        // Setup app domain separator (simulating an external app)
        EIP712Domain memory domain = EIP712Domain({
            name: "ExternalApp",
            version: "1",
            chainId: block.chainid,
            verifyingContract: address(0x1234567890123456789012345678901234567890)
        });
        appDomainSeparator = _hashEIP712Domain(domain);

        // Initialize test variables
        testContentHash = keccak256(abi.encode("testData", TEST_CONTENT_TYPE));
        testMessageHash = _toContentsHash(testContentHash);
    }

    /*//////////////////////////////////////////////////////////////
                              SMART SESSION
    //////////////////////////////////////////////////////////////*/

    function test_isValidSignatureWithSender_Success() public withEnabledSession {
        // Arrange
        TestTemps memory t = _prepareTestTemps();
        bytes memory signature = _createValidSignature(t);
        bytes memory fullSignature = abi.encodePacked(address(smartSessionEmissary), signature);

        // Act
        bytes4 result = IERC1271(instance.account).isValidSignature(testMessageHash, fullSignature);

        // Assert
        assertEq(result, ERC1271_MAGIC_VALUE, "Should return ERC1271 magic value");
    }

    function test_isValidSignatureWithSender_InvalidSignature()
        public
        withEnabledSessionWithFailingValidator
    {
        // Arrange
        TestTemps memory t = _prepareTestTemps();
        bytes memory signature = _createValidSignature(t);
        bytes memory fullSignature = abi.encodePacked(address(smartSessionEmissary), signature);

        // Act
        bytes4 result = IERC1271(instance.account).isValidSignature(testMessageHash, fullSignature);

        // Assert
        assertEq(result, INVALID_SIGNATURE, "Should return invalid signature");
    }

    function test_isValidSignatureWithSender_ERC7739Detection() public view {
        // Arrange - No session needed for detection
        bytes memory emptySignature = "";
        bytes memory fullSignature = abi.encodePacked(address(smartSessionEmissary), emptySignature);

        // Act
        bytes4 result = smartSessionEmissary.isValidSignatureWithSender(
            address(this), ERC7739_DETECTION_HASH, fullSignature
        );

        // Assert
        assertEq(result, ERC7739_SUPPORT_VALUE, "Should return ERC7739 support value");
    }

    function test_isValidSignatureWithSender_RejectsSessionAsSender() public withEnabledSession {
        // Arrange
        TestTemps memory t = _prepareTestTemps();
        bytes memory signature = _createValidSignature(t);
        bytes memory fullSignature = abi.encodePacked(address(smartSessionEmissary), signature);

        // Act - SmartSessionEmissary calling itself should be rejected
        bytes4 result = smartSessionEmissary.isValidSignatureWithSender(
            address(smartSessionEmissary), testMessageHash, fullSignature
        );

        // Assert
        assertEq(result, INVALID_SIGNATURE, "Should reject when sender is the session itself");
    }

    /*//////////////////////////////////////////////////////////////
                                  EDGE
    //////////////////////////////////////////////////////////////*/

    function test_isValidSignatureWithSender_RevertsWhen_InvalidPermissionId() public view {
        // Arrange
        PermissionId invalidPermissionId = PermissionId.wrap(bytes32(uint256(0xdead)));
        bytes memory signature = abi.encodePacked(invalidPermissionId, "mockData");
        bytes memory fullSignature = abi.encodePacked(address(smartSessionEmissary), signature);

        // Act
        bytes4 result = IERC1271(instance.account).isValidSignature(testMessageHash, fullSignature);

        // Assert
        assertEq(result, INVALID_SIGNATURE, "Should return invalid for non-existent permission");
    }

    function test_isValidSignatureWithSender_MalformedSignature() public withEnabledSession {
        // Arrange - Create malformed signature (too short)
        bytes memory malformedSignature = abi.encodePacked(testPermissionId, "short");
        bytes memory fullSignature =
            abi.encodePacked(address(smartSessionEmissary), malformedSignature);

        // Act
        bytes4 result = IERC1271(instance.account).isValidSignature(testMessageHash, fullSignature);

        // Assert
        assertEq(result, INVALID_SIGNATURE, "Should return invalid for malformed signature");
    }

    function test_isValidSignatureWithSender_RevertsWhen_WrongContentType()
        public
        withEnabledSession
    {
        // Arrange
        TestTemps memory t = _prepareTestTemps();
        string memory wrongContentType = "WrongContent(string data)";
        bytes32 wrongContentHash = keccak256(abi.encode("testData", wrongContentType));

        // Create signature with wrong content type
        (t.v, t.r, t.s) = vm.sign(
            t.privateKey,
            _toERC1271Hash(t.account, wrongContentHash, wrongContentType, "WrongContent")
        );

        bytes memory contentsDescription = abi.encodePacked(wrongContentType, "WrongContent");
        bytes memory signature = abi.encodePacked(
            t.r,
            t.s,
            t.v,
            appDomainSeparator,
            wrongContentHash,
            contentsDescription,
            uint16(contentsDescription.length)
        );

        signature = abi.encodePacked(testPermissionId, signature);
        bytes memory fullSignature = abi.encodePacked(address(smartSessionEmissary), signature);

        // Act
        bytes4 result = IERC1271(instance.account).isValidSignature(testMessageHash, fullSignature);

        // Assert
        assertEq(result, INVALID_SIGNATURE, "Should fail with wrong content type");
    }

    function test_isValidSignatureWithSender_RevertsWhen_DisabledContent()
        public
        withEnabledSession
    {
        // Arrange
        TestTemps memory t = _prepareTestTemps();
        // Create signature with content type that isn't enabled
        string memory disabledContentType = "DisabledContent(uint256 value)";
        bytes32 disabledContentHash = keccak256(abi.encode(uint256(123), disabledContentType));
        bytes32 disabledMessageHash = _toContentsHash(disabledContentHash);

        (t.v, t.r, t.s) = vm.sign(
            t.privateKey,
            _toERC1271Hash(t.account, disabledContentHash, disabledContentType, "DisabledContent")
        );

        bytes memory contentsDescription = abi.encodePacked(disabledContentType, "DisabledContent");
        bytes memory signature = abi.encodePacked(
            t.r,
            t.s,
            t.v,
            appDomainSeparator,
            disabledContentHash,
            contentsDescription,
            uint16(contentsDescription.length)
        );

        signature = abi.encodePacked(testPermissionId, signature);
        bytes memory fullSignature = abi.encodePacked(address(smartSessionEmissary), signature);

        // Act
        bytes4 result =
            IERC1271(instance.account).isValidSignature(disabledMessageHash, fullSignature);

        // Assert
        assertEq(result, INVALID_SIGNATURE, "Should fail with disabled content type");
    }

    /*//////////////////////////////////////////////////////////////
                                 CACHE
    //////////////////////////////////////////////////////////////*/

    function test_isValidSignatureWithSender_WithERC6492Wrapper() public withEnabledSession {
        // Arrange
        TestTemps memory t = _prepareTestTemps();
        bytes memory signature = _createValidSignature(t);

        // Wrap with ERC6492
        bytes memory wrappedSignature = _erc6492Wrap(signature);
        bytes memory fullSignature =
            abi.encodePacked(address(smartSessionEmissary), wrappedSignature);

        // Act
        bytes4 result = IERC1271(instance.account).isValidSignature(testMessageHash, fullSignature);

        // Assert
        assertEq(result, ERC1271_MAGIC_VALUE, "Should handle ERC6492 wrapped signature");
    }

    /*//////////////////////////////////////////////////////////////
                               MODIFIERS
    //////////////////////////////////////////////////////////////*/

    modifier withEnabledSession() {
        // Prank to account
        vm.prank(instance.account);

        // Setup policies
        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });

        // Setup ERC7739 data with enabled content
        ERC7739Context[] memory allowedContent = new ERC7739Context[](1);
        allowedContent[0].contentNames =
            Solarray.strings(string(abi.encodePacked(TEST_CONTENT_TYPE, TEST_CONTENT_NAME)));
        allowedContent[0].appDomainSeparator = appDomainSeparator;

        ERC7739Data memory erc7739Data =
            ERC7739Data({ allowedERC7739Content: allowedContent, erc1271Policies: policyDatas });

        // Setup session
        Session memory session = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: keccak256("signatureSalt"),
            sessionValidatorInitData: "mockInitData",
            erc7739Policies: erc7739Data,
            actions: new ActionData[](0),
            claimPolicies: new PolicyData[](0)
        });

        // Enable session
        Session[] memory sessions = new Session[](1);
        sessions[0] = session;
        bytes12 lockTag = bytes12(0); // NO_LOCKTAG for 1271 only

        PermissionId[] memory permissionIds = smartSessionEmissary.enableSessions(sessions, lockTag);
        testPermissionId = permissionIds[0];

        // Continue with the test
        _;
    }

    modifier withEnabledSessionWithFailingValidator() {
        // Prank to account
        vm.prank(instance.account);

        // Setup policies
        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });

        // Setup ERC7739 data with enabled content
        ERC7739Context[] memory allowedContent = new ERC7739Context[](1);
        allowedContent[0].contentNames =
            Solarray.strings(string(abi.encodePacked(TEST_CONTENT_TYPE, TEST_CONTENT_NAME)));
        allowedContent[0].appDomainSeparator = appDomainSeparator;

        ERC7739Data memory erc7739Data =
            ERC7739Data({ allowedERC7739Content: allowedContent, erc1271Policies: policyDatas });

        // Setup session with failing validator
        Session memory session = Session({
            sessionValidator: ISessionValidator(address(noSessionValidator)),
            salt: keccak256("failingSignatureSalt"),
            sessionValidatorInitData: "mockInitData",
            erc7739Policies: erc7739Data,
            actions: new ActionData[](0),
            claimPolicies: new PolicyData[](0)
        });

        // Enable session
        Session[] memory sessions = new Session[](1);
        sessions[0] = session;
        bytes12 lockTag = bytes12(0); // NO_LOCKTAG for 1271 only

        PermissionId[] memory permissionIds = smartSessionEmissary.enableSessions(sessions, lockTag);
        testPermissionId = permissionIds[0];

        // Continue with the test
        _;
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    function _prepareTestTemps() internal returns (TestTemps memory t) {
        t.owner = makeAddr("owner");
        t.signer = sessionSigner.addr;
        t.privateKey = sessionSigner.key;
        t.chainId = block.chainid;
        t.salt = keccak256(abi.encodePacked("test"));
        t.account = instance.account;
    }

    function _createValidSignature(TestTemps memory t) internal view returns (bytes memory) {
        // Sign the message
        (t.v, t.r, t.s) = vm.sign(
            t.privateKey,
            _toERC1271Hash(t.account, testContentHash, TEST_CONTENT_TYPE, TEST_CONTENT_NAME)
        );

        // Create validator signature
        bytes memory validatorSignature = abi.encodePacked(t.r, t.s, t.v);

        // Create contents description
        bytes memory contentsDescription = abi.encodePacked(TEST_CONTENT_TYPE, TEST_CONTENT_NAME);

        // Create signature with ERC7739 wrapper
        bytes memory signatureWithWrapper = abi.encodePacked(
            validatorSignature,
            appDomainSeparator,
            testContentHash,
            contentsDescription,
            uint16(contentsDescription.length)
        );

        // Calculate policyDataOffset: 64 (permissionId + offset field) + validatorSig length
        uint256 policyDataOffset = 64 + validatorSignature.length;

        // Return complete signature
        return abi.encodePacked(
            bytes1(0x01), // 7739 mode
            testPermissionId,
            policyDataOffset,
            signatureWithWrapper
        );
    }

    function _erc6492Wrap(bytes memory signature) internal pure returns (bytes memory) {
        return abi.encodePacked(
            abi.encode(address(0x1234), "deploymentData", signature),
            bytes32(0x6492649264926492649264926492649264926492649264926492649264926492)
        );
    }

    function _toERC1271Hash(
        address account,
        bytes32 contents,
        string memory contentsType,
        string memory contentsName
    )
        internal
        view
        returns (bytes32)
    {
        bytes32 parentStructHash = keccak256(
            abi.encodePacked(
                abi.encode(_typedDataSignTypeHash(contentsType, contentsName), contents),
                _accountDomainStructFields(account)
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", appDomainSeparator, parentStructHash));
    }

    function _accountDomainStructFields(address account) internal view returns (bytes memory) {
        (
            ,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
        ) = EIP712(account).eip712Domain();

        return abi.encode(
            keccak256(bytes(name)), keccak256(bytes(version)), chainId, verifyingContract, salt
        );
    }

    function _typedDataSignTypeHash(
        string memory contentsType,
        string memory contentsName
    )
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encodePacked(
                "TypedDataSign(",
                contentsName,
                " contents,string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)",
                contentsType
            )
        );
    }

    function _toContentsHash(bytes32 contents) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(hex"1901", appDomainSeparator, contents));
    }

    function _hashEIP712Domain(EIP712Domain memory domain) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256(bytes(domain.name)),
                keccak256(bytes(domain.version)),
                domain.chainId,
                domain.verifyingContract
            )
        );
    }

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    struct EIP712Domain {
        string name;
        string version;
        uint256 chainId;
        address verifyingContract;
    }
}
