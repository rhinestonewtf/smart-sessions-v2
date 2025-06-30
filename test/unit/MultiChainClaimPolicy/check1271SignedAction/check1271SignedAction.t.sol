// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { MultiChainClaimPolicy_Unit_Test } from
    "@test/unit/MultiChainClaimPolicy/MultiChainClaimPolicy.t.sol";

// Libraries
import { ConfigLib, PolicyConfig } from "@policies/claim-recipient/lib/ConfigLib.sol";
import { HashLib } from "@policies/claim-recipient/lib/HashLib.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";

contract MultiChainClaimPolicy_check1271SignedAction_Test is MultiChainClaimPolicy_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                 VARIABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice Test account
    address internal testAccount;

    /// @notice Test config ID
    ConfigId internal testConfigId;

    /// @notice Empty executions hash constant
    bytes32 internal constant EMPTY_EXECUTIONS_HASH =
        0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470;

    /*//////////////////////////////////////////////////////////////
                                   SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        // Call the base setup function (which deploys multiChainClaimPolicy).
        super.setUp();

        // Set up test accounts and config ID
        testAccount = makeAddr("testAccount");
        testConfigId = ConfigId.wrap(bytes32(uint256(1)));
    }

    /*//////////////////////////////////////////////////////////////
                              HASEXECUTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test check1271SignedAction with hasExecutions condition - should pass when
    ///         executions present
    function test_check1271SignedAction_hasExecutions_withExecutions_shouldPass() public {
        // Initialize policy with CHECK_HAS_EXECUTIONS
        _initializePolicyWithHasExecutions();

        // Create MultiChainCompact data with executions present (non-empty hash)
        bytes32 nonEmptyTargetOpsHash = keccak256("some executions");
        bytes memory compactData = _createBasicMultiChainCompactData(nonEmptyTargetOpsHash);

        // Compute expected hash
        bytes32 expectedHash = this.computeExpectedHash(compactData);

        // Check the action
        bool result = multiChainClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr, // sender
            testAccount,
            expectedHash,
            compactData // signature contains the raw compact data
        );

        assertTrue(result, "Action with executions should be allowed");
    }

    /// @notice Test check1271SignedAction with hasExecutions condition - should fail when no
    ///         executions
    function test_check1271SignedAction_hasExecutions_withoutExecutions_shouldFail() public {
        // Initialize policy with CHECK_HAS_EXECUTIONS
        _initializePolicyWithHasExecutions();

        // Create MultiChainCompact data with no executions (empty hash)
        bytes memory compactData = _createBasicMultiChainCompactData(EMPTY_EXECUTIONS_HASH);

        // Compute expected hash
        bytes32 expectedHash = this.computeExpectedHash(compactData);

        // Check the action
        bool result = multiChainClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr, // sender
            testAccount,
            expectedHash,
            compactData // signature contains the raw compact data
        );

        assertFalse(result, "Action without executions should be rejected");
    }

    /// @notice Test check1271SignedAction in sudo mode (no conditions) - should pass regardless of
    ///         executions
    function test_check1271SignedAction_sudoMode_shouldAlwaysPass() public {
        // Initialize policy with no conditions (bitmap = 0)
        uint8 conditionsBitmap = 0;
        bytes memory initData = abi.encodePacked(conditionsBitmap);

        multiChainClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);

        // Create MultiChainCompact data with empty executions (should normally fail with
        // hasExecutions condition)
        bytes memory compactData = _createBasicMultiChainCompactData(EMPTY_EXECUTIONS_HASH);

        // Compute expected hash
        bytes32 expectedHash = this.computeExpectedHash(compactData);

        // Check the action
        bool result = multiChainClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr, // sender
            testAccount,
            expectedHash,
            compactData // signature contains the raw compact data
        );

        assertTrue(result, "Sudo mode should allow all actions regardless of executions");
    }

    /// @notice Test check1271SignedAction with hasExecutions condition - should fail when hash
    ///         mismatch
    function test_check1271SignedAction_hasExecutions_wrongHash_shouldFail() public {
        // Initialize policy with CHECK_HAS_EXECUTIONS
        _initializePolicyWithHasExecutions();

        // Create MultiChainCompact data with executions present
        bytes32 nonEmptyTargetOpsHash = keccak256("some executions");
        bytes memory compactData = _createBasicMultiChainCompactData(nonEmptyTargetOpsHash);

        // Use a wrong hash (different from the computed one)
        bytes32 wrongHash = keccak256("wrong hash");

        // Check the action
        bool result = multiChainClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr, // sender
            testAccount,
            wrongHash,
            compactData // signature contains the raw compact data
        );

        assertFalse(result, "Action should fail when hash doesn't match");
    }

    /*//////////////////////////////////////////////////////////////
                                 HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Helper function to create a basic MultiChainCompact data structure
    function _createBasicMultiChainCompactData(bytes32 targetOpsHash)
        internal
        view
        returns (bytes memory)
    {
        // Create basic MultiChainCompact data with minimal required fields
        // Structure: sponsor(20) + nonce(32) + expires(32) + otherElements(32+0) +
        //           arbiter(20) + reserved(12) + chainId(32) + commitmentsHash(32) +
        //           targetHash(32) + preClaimOpsHash(32) + targetOpsHash(32) +
        //           qualificationHash(32)

        bytes memory data = abi.encodePacked(
            address(0x1234567890123456789012345678901234567890), // sponsor (20 bytes)
            uint256(1), // nonce (32 bytes)
            uint256(block.timestamp + 3600), // expires (32 bytes)
            uint256(0), // otherElements length (32 bytes)
            // No otherElements data since length is 0
            address(0x9876543210987654321098765432109876543210), // arbiter (20 bytes)
            bytes12(0), // reserved space (12 bytes)
            uint256(1), // chainId (32 bytes)
            keccak256("commitments"), // commitmentsHash (32 bytes)
            keccak256("target"), // targetHash (32 bytes)
            keccak256("preClaimOps"), // preClaimOpsHash (32 bytes)
            targetOpsHash, // targetOpsHash (32 bytes)
            keccak256("qualification") // qualificationHash (32 bytes)
        );

        return data;
    }

    /// @notice Helper function to initialize policy with hasExecutions condition
    function _initializePolicyWithHasExecutions() internal {
        // Create policy config with only CHECK_HAS_EXECUTIONS enabled (bit 0)
        uint8 conditionsBitmap = 1; // Binary: 00000001

        // Create initialization data (just the bitmap since hasExecutions needs no extra config)
        bytes memory initData = abi.encodePacked(conditionsBitmap);

        // Initialize the policy
        multiChainClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    /// @notice Helper function to compute the expected hash for the MultiChainCompact
    function computeExpectedHash(bytes calldata compactData) public pure returns (bytes32) {
        // Parse the compact data to extract individual fields
        address sponsor = address(bytes20(compactData[0:20]));
        uint256 nonce = uint256(bytes32(compactData[20:52]));
        uint256 expires = uint256(bytes32(compactData[52:84]));

        // Skip otherElements (length is 0, so just 32 bytes for length)
        uint256 offset = 84 + 32; // 116

        // Parse element data
        address arbiter = address(bytes20(compactData[offset:offset + 20]));
        offset += 32; // Skip arbiter + reserved space (20 + 12 = 32)
        uint256 chainId = uint256(bytes32(compactData[offset:offset + 32]));
        offset += 32;
        bytes32 commitmentsHash = bytes32(compactData[offset:offset + 32]);
        offset += 32;
        bytes32 targetHash = bytes32(compactData[offset:offset + 32]);
        offset += 32;
        bytes32 preClaimOpsHash = bytes32(compactData[offset:offset + 32]);
        offset += 32;
        bytes32 targetOpsHash = bytes32(compactData[offset:offset + 32]);
        offset += 32;
        bytes32 qualificationHash = bytes32(compactData[offset:offset + 32]);

        // Hash the mandate
        bytes32 mandateHash =
            HashLib.hashMandate(targetHash, preClaimOpsHash, targetOpsHash, qualificationHash);

        // Hash the element
        bytes32 notarizedElementHash =
            HashLib.hashElement(arbiter, chainId, commitmentsHash, mandateHash);

        // Create empty otherElements array
        bytes32[] memory otherElements = new bytes32[](0);

        // Hash the compact
        return HashLib.hashCompact(sponsor, nonce, expires, notarizedElementHash, otherElements);
    }
}
