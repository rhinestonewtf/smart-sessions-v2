// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { MultiChainClaimRecipient_Unit_Test } from
    "@test/integration/MultiChainClaimRecipientPolicy/MultiChainClaimRecipient.t.sol";
import { MultiChainClaimRecipientPolicy } from
    "@policies/claim-recipient/MultiChainClaimRecipientPolicy.sol";

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

contract MultiChainClaimRecipient_verifyClaim_Integration_Test is
    MultiChainClaimRecipient_Unit_Test,
    MultiChainClaimRecipientPolicy
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
    bytes12 testLockTag;
    bytes32 testClaimHash;
    bytes32 testDigest;
    bytes32 appDomainSeparator;
    string constant TEST_CONTENT = "TestContent(string data)";
    string constant TEST_CONTENT_NAME = "TestContent";
    bytes mockERC7739Signature;

    address constant TEST_RECIPIENT = 0x0000000000000000000000000000000000000B0b;
    address constant TEST_ARBITER = 0xa1B1710000000000000000000000000000000000;
    address constant TEST_SPONSOR = 0x9123501000000000000000000000000000000000;

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

    /*//////////////////////////////////////////////////////////////
                               MODIFIERS
    //////////////////////////////////////////////////////////////*/

    modifier withEnabledClaimSession() {
        // Prank to account
        vm.prank(instance.account);

        // Setup ERC-7739 content policies
        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({
            policy: address(multiChainClaimRecipient),
            initData: abi.encode(address(0xb0b))
        });

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

        // Set a mock lockTag for testing
        testLockTag = bytes12(keccak256("mockLockTag"));

        smartSessionEmissary.enableSessions(sessions, testLockTag, address(this));

        // Generate the permission ID
        testPermissionId = smartSessionEmissary.getPermissionId(session);

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

    function _createMockMultichainCompact() internal returns (bytes memory) {
        // Create mock target
        Target memory target = Target({
            recipient: TEST_RECIPIENT,
            tokenOut: keccak256("mockTokenOut"), // Mock token out hash
            targetChain: 1, // Ethereum mainnet
            fillExpires: block.timestamp + 3600 // 1 hour from now
         });

        // Create mock mandate
        Mandate memory mandate = Mandate({
            target: target,
            preClaimOps: keccak256("mockPreClaimOps"), // Mock pre-claim ops hash
            targetOps: keccak256("mockTargetOps"), // Mock target ops hash
            q: keccak256("mockQualifier") // Mock qualifier hash
         });

        // Create mock notarized element
        Element memory notarizedElement = Element({
            arbiter: TEST_ARBITER,
            chainId: block.chainid,
            commitments: keccak256("mockCommitments"), // Mock commitments hash
            mandate: mandate
        });

        // Create mock other elements (empty for simplicity)
        bytes32[] memory otherElements = new bytes32[](2);
        otherElements[0] = keccak256("mockOtherElement1");
        otherElements[1] = keccak256("mockOtherElement2");

        // Create the complete MultichainCompact struct
        MultichainCompact memory multichainCompact = MultichainCompact({
            sponsor: TEST_SPONSOR,
            nonce: 12_345,
            expires: block.timestamp + 7200, // 2 hours from now
            notarizedElement: notarizedElement,
            otherElements: otherElements
        });

        testDigest = _rehashMultichainCompact(multichainCompact);

        // Encode and return the struct
        return abi.encode(multichainCompact);
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
            contents
        );

        // Prepend the permissionId and extraStuff to the session signature
        bytes memory extraStuff = _createMockMultichainCompact();
        mockERC7739Signature = abi.encodePacked(
            testPermissionId, bytes32(extraStuff.length), extraStuff, sessionSignature
        );
    }
}
