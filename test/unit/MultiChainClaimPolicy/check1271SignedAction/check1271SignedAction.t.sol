// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { MultiChainClaimPolicy_Unit_Test } from
    "@test/unit/MultiChainClaimPolicy/MultiChainClaimPolicy.t.sol";

// Libraries
import { ConfigLib, PolicyConfig } from "@policies/claim-recipient/lib/ConfigLib.sol";
import { HashLib } from "@policies/claim-recipient/lib/HashLib.sol";
import { ArgPolicyTreeLib } from
    "@smartsessions/external/policies/ArgPolicy/lib/ArgPolicyTreeLib.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import {
    Lock, Token, Op, ParamRules, ParamRule
} from "@policies/claim-recipient/types/DataTypes.sol";
import { ParamCondition } from "@smartsessions/external/policies/ArgPolicy/ArgPolicy.sol";

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
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    //-------------------------------------
    // 1) EXECUTIONS
    //-------------------------------------

    /// @notice Test check1271SignedAction with hasExecutions condition - should pass when
    /// executions present
    function test_check1271SignedAction_hasExecutions_withExecutions_shouldPass() public {
        // Initialize policy with CHECK_HAS_EXECUTIONS
        _initializePolicyWithHasExecutions();

        // Create MultiChainCompact data with executions present (non-empty hash)
        bytes32 nonEmptyTargetOpsHash = keccak256("some executions");
        bytes memory compactData = _createMultiChainCompactDataWithTargetOps(nonEmptyTargetOpsHash);

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
    /// executions
    function test_check1271SignedAction_hasExecutions_withoutExecutions_shouldFail() public {
        // Initialize policy with CHECK_HAS_EXECUTIONS
        _initializePolicyWithHasExecutions();

        // Create MultiChainCompact data with no executions (empty hash)
        bytes memory compactData = _createMultiChainCompactDataWithTargetOps(EMPTY_EXECUTIONS_HASH);

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
    /// executions
    function test_check1271SignedAction_sudoMode_shouldAlwaysPass() public {
        // Initialize policy with no conditions (bitmap = 0)
        uint8 conditionsBitmap = 0;
        bytes memory initData = abi.encodePacked(conditionsBitmap);

        multiChainClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);

        // Create MultiChainCompact data with empty executions (should normally fail with
        // hasExecutions condition)
        bytes memory compactData = _createMultiChainCompactDataWithTargetOps(EMPTY_EXECUTIONS_HASH);

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
    /// mismatch
    function test_check1271SignedAction_hasExecutions_wrongHash_shouldFail() public {
        // Initialize policy with CHECK_HAS_EXECUTIONS
        _initializePolicyWithHasExecutions();

        // Create MultiChainCompact data with executions present
        bytes32 nonEmptyTargetOpsHash = keccak256("some executions");
        bytes memory compactData = _createMultiChainCompactDataWithTargetOps(nonEmptyTargetOpsHash);

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

    //-------------------------------------
    // 2) TOKEN IN
    //-------------------------------------

    /// @notice Test check1271SignedAction with tokenIn condition - should pass when token and
    /// amount are valid
    function test_check1271SignedAction_tokenIn_validTokenAndAmount_shouldPass() public {
        address testToken = makeAddr("testToken");
        uint128 minAmount = 100;
        uint128 maxAmount = 1000;
        uint256 testAmount = 500; // Within range

        // Initialize policy with CHECK_TOKEN_IN
        _initializePolicyWithTokenIn(testToken, minAmount, maxAmount);

        // Create MultiChainCompact data with valid token and amount
        bytes memory compactData = _createMultiChainCompactDataWithTokenIn(testToken, testAmount);

        // Compute expected hash
        bytes32 expectedHash = this.computeExpectedHashWithTokenIn(compactData);

        // Check the action
        bool result = multiChainClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr, // sender
            testAccount,
            expectedHash,
            compactData
        );

        assertTrue(result, "Action with valid token and amount should be allowed");
    }

    /// @notice Test check1271SignedAction with tokenIn condition - should fail when token address
    /// is invalid
    function test_check1271SignedAction_tokenIn_invalidToken_shouldFail() public {
        address testToken = makeAddr("testToken");
        address wrongToken = makeAddr("wrongToken");
        uint128 minAmount = 100;
        uint128 maxAmount = 1000;
        uint256 testAmount = 500;

        // Initialize policy with CHECK_TOKEN_IN for testToken
        _initializePolicyWithTokenIn(testToken, minAmount, maxAmount);

        // Create MultiChainCompact data with wrong token
        bytes memory compactData = _createMultiChainCompactDataWithTokenIn(wrongToken, testAmount);

        // Compute expected hash
        bytes32 expectedHash = this.computeExpectedHashWithTokenIn(compactData);

        // Check the action
        bool result = multiChainClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr, // sender
            testAccount,
            expectedHash,
            compactData
        );

        assertFalse(result, "Action with invalid token should be rejected");
    }

    /// @notice Test check1271SignedAction with tokenIn condition - should fail when amount is below
    /// minimum
    function test_check1271SignedAction_tokenIn_amountBelowMin_shouldFail() public {
        address testToken = makeAddr("testToken");
        uint128 minAmount = 100;
        uint128 maxAmount = 1000;
        uint256 testAmount = 50; // Below minimum

        // Initialize policy with CHECK_TOKEN_IN
        _initializePolicyWithTokenIn(testToken, minAmount, maxAmount);

        // Create MultiChainCompact data with amount below minimum
        bytes memory compactData = _createMultiChainCompactDataWithTokenIn(testToken, testAmount);

        // Compute expected hash
        bytes32 expectedHash = this.computeExpectedHashWithTokenIn(compactData);

        // Check the action
        bool result = multiChainClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr, // sender
            testAccount,
            expectedHash,
            compactData
        );

        assertFalse(result, "Action with amount below minimum should be rejected");
    }

    /// @notice Test check1271SignedAction with tokenIn condition - should fail when amount is above
    /// maximum
    function test_check1271SignedAction_tokenIn_amountAboveMax_shouldFail() public {
        address testToken = makeAddr("testToken");
        uint128 minAmount = 100;
        uint128 maxAmount = 1000;
        uint256 testAmount = 1500; // Above maximum

        // Initialize policy with CHECK_TOKEN_IN
        _initializePolicyWithTokenIn(testToken, minAmount, maxAmount);

        // Create MultiChainCompact data with amount above maximum
        bytes memory compactData = _createMultiChainCompactDataWithTokenIn(testToken, testAmount);

        // Compute expected hash
        bytes32 expectedHash = this.computeExpectedHashWithTokenIn(compactData);

        // Check the action
        bool result = multiChainClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr, // sender
            testAccount,
            expectedHash,
            compactData
        );

        assertFalse(result, "Action with amount above maximum should be rejected");
    }

    /// @notice Test check1271SignedAction with tokenIn condition - should pass with any token when
    /// address(0) configured
    function test_check1271SignedAction_tokenIn_anyToken_shouldPass() public {
        address anyToken = address(0); // address(0) means any token is allowed
        address testToken = makeAddr("testToken");
        uint128 minAmount = 100;
        uint128 maxAmount = 1000;
        uint256 testAmount = 500;

        // Initialize policy with CHECK_TOKEN_IN for any token (address(0))
        _initializePolicyWithTokenIn(anyToken, minAmount, maxAmount);

        // Create MultiChainCompact data with specific token (should be allowed since any token is
        // configured)
        bytes memory compactData = _createMultiChainCompactDataWithTokenIn(testToken, testAmount);

        // Compute expected hash
        bytes32 expectedHash = this.computeExpectedHashWithTokenIn(compactData);

        // Check the action
        bool result = multiChainClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr, // sender
            testAccount,
            expectedHash,
            compactData
        );

        assertTrue(result, "Action with any token should be allowed when address(0) is configured");
    }

    //-------------------------------------
    // 3) TOKEN OUT
    //-------------------------------------

    /// @notice Test check1271SignedAction with tokenOut condition - should pass when token and
    /// amount are valid
    function test_check1271SignedAction_tokenOut_validTokenAndAmount_shouldPass() public {
        address testToken = makeAddr("testToken");
        uint128 minAmount = 200;
        uint128 maxAmount = 2000;
        uint256 testAmount = 1000; // Within range
        uint256 targetChainId = 137; // Polygon

        // Initialize policy with CHECK_TOKEN_OUT
        _initializePolicyWithTokenOut(testToken, minAmount, maxAmount, targetChainId);

        // Create MultiChainCompact data with valid token and amount
        bytes memory compactData =
            _createMultiChainCompactDataWithTokenOut(testToken, testAmount, targetChainId);

        // Compute expected hash
        bytes32 expectedHash = this.computeExpectedHashWithTokenOut(compactData);

        // Check the action
        bool result = multiChainClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr, // sender
            testAccount,
            expectedHash,
            compactData
        );

        assertTrue(result, "Action with valid tokenOut should be allowed");
    }

    /// @notice Test check1271SignedAction with tokenOut condition - should fail when token address
    /// is invalid
    function test_check1271SignedAction_tokenOut_invalidToken_shouldFail() public {
        address testToken = makeAddr("testToken");
        address wrongToken = makeAddr("wrongToken");
        uint128 minAmount = 200;
        uint128 maxAmount = 2000;
        uint256 testAmount = 1000;
        uint256 targetChainId = 137;

        // Initialize policy with CHECK_TOKEN_OUT for testToken
        _initializePolicyWithTokenOut(testToken, minAmount, maxAmount, targetChainId);

        // Create MultiChainCompact data with wrong token
        bytes memory compactData =
            _createMultiChainCompactDataWithTokenOut(wrongToken, testAmount, targetChainId);

        // Compute expected hash
        bytes32 expectedHash = this.computeExpectedHashWithTokenOut(compactData);

        // Check the action
        bool result = multiChainClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr, // sender
            testAccount,
            expectedHash,
            compactData
        );

        assertFalse(result, "Action with invalid tokenOut should be rejected");
    }

    /// @notice Test check1271SignedAction with tokenOut condition - should fail when amount is
    /// below minimum
    function test_check1271SignedAction_tokenOut_amountBelowMin_shouldFail() public {
        address testToken = makeAddr("testToken");
        uint128 minAmount = 200;
        uint128 maxAmount = 2000;
        uint256 testAmount = 100; // Below minimum
        uint256 targetChainId = 137;

        // Initialize policy with CHECK_TOKEN_OUT
        _initializePolicyWithTokenOut(testToken, minAmount, maxAmount, targetChainId);

        // Create MultiChainCompact data with amount below minimum
        bytes memory compactData =
            _createMultiChainCompactDataWithTokenOut(testToken, testAmount, targetChainId);

        // Compute expected hash
        bytes32 expectedHash = this.computeExpectedHashWithTokenOut(compactData);

        // Check the action
        bool result = multiChainClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr, // sender
            testAccount,
            expectedHash,
            compactData
        );

        assertFalse(result, "Action with tokenOut amount below minimum should be rejected");
    }

    /// @notice Test check1271SignedAction with tokenOut condition - should fail when amount is
    /// above maximum
    function test_check1271SignedAction_tokenOut_amountAboveMax_shouldFail() public {
        address testToken = makeAddr("testToken");
        uint128 minAmount = 200;
        uint128 maxAmount = 2000;
        uint256 testAmount = 3000; // Above maximum
        uint256 targetChainId = 137;

        // Initialize policy with CHECK_TOKEN_OUT
        _initializePolicyWithTokenOut(testToken, minAmount, maxAmount, targetChainId);

        // Create MultiChainCompact data with amount above maximum
        bytes memory compactData =
            _createMultiChainCompactDataWithTokenOut(testToken, testAmount, targetChainId);

        // Compute expected hash
        bytes32 expectedHash = this.computeExpectedHashWithTokenOut(compactData);

        // Check the action
        bool result = multiChainClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr, // sender
            testAccount,
            expectedHash,
            compactData
        );

        assertFalse(result, "Action with tokenOut amount above maximum should be rejected");
    }

    /// @notice Test check1271SignedAction with tokenOut condition - should pass with any token when
    /// address(0) configured
    function test_check1271SignedAction_tokenOut_anyToken_shouldPass() public {
        address anyToken = address(0); // address(0) means any token is allowed
        address testToken = makeAddr("testToken");
        uint128 minAmount = 200;
        uint128 maxAmount = 2000;
        uint256 testAmount = 1000;
        uint256 targetChainId = 137;

        // Initialize policy with CHECK_TOKEN_OUT for any token (address(0))
        _initializePolicyWithTokenOut(anyToken, minAmount, maxAmount, targetChainId);

        // Create MultiChainCompact data with specific token (should be allowed since any token is
        // configured)
        bytes memory compactData =
            _createMultiChainCompactDataWithTokenOut(testToken, testAmount, targetChainId);

        // Compute expected hash
        bytes32 expectedHash = this.computeExpectedHashWithTokenOut(compactData);

        // Check the action
        bool result = multiChainClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr, // sender
            testAccount,
            expectedHash,
            compactData
        );

        assertTrue(
            result, "Action with any tokenOut should be allowed when address(0) is configured"
        );
    }

    //-------------------------------------
    // 4) QUALIFICATION
    //-------------------------------------

    /// @notice Test check1271SignedAction with qualification condition - should pass when
    /// qualification matches rules
    function test_check1271SignedAction_qualification_validData_shouldPass() public {
        // Initialize policy with CHECK_QUALIFICATION
        _initializePolicyWithQualification();

        // Create MultiChainCompact data with valid qualification
        bytes memory compactData = _createMultiChainCompactDataWithQualification(true);

        // Compute expected hash
        bytes32 expectedHash = this.computeExpectedHashWithQualification(compactData);

        // Check the action
        bool result = multiChainClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr, // sender
            testAccount,
            expectedHash,
            compactData
        );

        assertTrue(result, "Action with valid qualification should be allowed");
    }

    /// @notice Test check1271SignedAction with qualification condition - should fail when
    /// qualification doesn't match rules
    function test_check1271SignedAction_qualification_invalidData_shouldFail() public {
        // Initialize policy with CHECK_QUALIFICATION
        _initializePolicyWithQualification();

        // Create MultiChainCompact data with invalid qualification
        bytes memory compactData = _createMultiChainCompactDataWithQualification(false);

        // Compute expected hash
        bytes32 expectedHash = this.computeExpectedHashWithQualification(compactData);

        // Check the action
        bool result = multiChainClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr, // sender
            testAccount,
            expectedHash,
            compactData
        );

        assertFalse(result, "Action with invalid qualification should be rejected");
    }

    /*//////////////////////////////////////////////////////////////
                                 HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Helper function to create a basic MultiChainCompact data structure
    function _createMultiChainCompactDataWithTargetOps(bytes32 targetOpsHash)
        internal
        view
        returns (bytes memory)
    {
        bytes memory header = _createCompactHeader();
        bytes memory elementHeader = _createElementHeader();
        bytes memory mandateData = _createMandateData(targetOpsHash);

        return abi.encodePacked(header, elementHeader, keccak256("commitments"), mandateData);
    }

    /// @notice Helper function to create MultiChainCompact data with tokenIn (Lock structs)
    function _createMultiChainCompactDataWithTokenIn(
        address token,
        uint256 amount
    )
        internal
        view
        returns (bytes memory)
    {
        bytes memory header = _createCompactHeader();
        bytes memory elementHeader = _createElementHeader();
        bytes memory lockData = _createLockData(token, amount);
        bytes memory mandateData = _createMandateData();

        return abi.encodePacked(header, elementHeader, uint256(1), lockData, mandateData);
    }

    /// @notice Helper function to create MultiChainCompact data with tokenOut
    function _createMultiChainCompactDataWithTokenOut(
        address token,
        uint256 amount,
        uint256 targetChainId
    )
        internal
        returns (bytes memory)
    {
        bytes memory header = _createCompactHeader();
        bytes memory elementHeader = _createElementHeader();
        bytes memory targetData = _createTargetData(token, amount, targetChainId);
        bytes memory mandateFooter = _createMandateFooter();

        return abi.encodePacked(
            header, elementHeader, keccak256("commitments"), targetData, mandateFooter
        );
    }

    /// @notice Helper function to create MultiChainCompact data with preClaimOps
    function _createMultiChainCompactDataWithPreClaimOps(bool isValid)
        internal
        view
        returns (bytes memory)
    {
        bytes memory header = _createCompactHeader();
        bytes memory elementHeader = _createElementHeader();
        bytes memory preClaimOpsData = _createPreClaimOpsData(isValid);
        bytes memory mandateWithPreClaimOps = _createMandateDataWithPreClaimOps(preClaimOpsData);

        return abi.encodePacked(
            header, elementHeader, keccak256("commitments"), mandateWithPreClaimOps
        );
    }

    /// @notice Helper function to create MultiChainCompact data with qualification
    function _createMultiChainCompactDataWithQualification(bool isValid)
        internal
        view
        returns (bytes memory)
    {
        bytes memory header = _createCompactHeader();
        bytes memory elementHeader = _createElementHeader();
        bytes memory qualificationData = _createQualificationData(isValid);
        bytes memory mandateWithQualification =
            _createMandateDataWithQualification(qualificationData);

        return abi.encodePacked(
            header, elementHeader, keccak256("commitments"), mandateWithQualification
        );
    }

    /// @notice Create preClaimOps data for testing - using function selector validation
    function _createPreClaimOpsData(bool isValid) private pure returns (bytes memory) {
        // Create function call data with different selectors for valid/invalid cases
        bytes memory functionCallData = isValid
            ? abi.encodeWithSignature("allowedFunction(uint256)", uint256(123)) // This selector
                // will match our rule
            : abi.encodeWithSignature("forbiddenFunction(uint256)", uint256(123)); // This selector
            // won't match

        // Encode in abi.encode(to, value, data) format
        // Layout: [0-31: to][32-63: value][64-95: data.length][96+: functionCallData]
        // Function selector is at position 96
        address to = address(0x1234567890123456789012345678901234567890);
        uint256 value = 0;
        bytes memory opData = abi.encode(to, value, functionCallData);

        return abi.encodePacked(
            uint256(1), // ops length
            uint256(opData.length), // op data length
            opData // op data
        );
    }

    /// @notice Create qualification data for testing
    function _createQualificationData(bool isValid) private pure returns (bytes memory) {
        // Create qualification data that will pass or fail validation
        bytes32 typehash = keccak256("TestQualification(uint256 value)");
        bytes memory qualData = isValid
            ? abi.encode(uint256(0x1234567890123456789012345678901234567890123456789012345678901234))
            : abi.encode(uint256(0x9999999999999999999999999999999999999999999999999999999999999999));

        return abi.encodePacked(
            uint256(qualData.length), // qualification data length
            typehash, // qualification typehash
            qualData // qualification data
        );
    }

    /// @notice Create mandate data with preClaimOps
    function _createMandateDataWithPreClaimOps(bytes memory preClaimOpsData)
        private
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            keccak256("target"), // targetHash
            preClaimOpsData, // preClaimOps data
            keccak256("targetOps"), // targetOpsHash
            keccak256("qualification") // qualificationHash
        );
    }

    /// @notice Create mandate data with qualification
    function _createMandateDataWithQualification(bytes memory qualificationData)
        private
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            keccak256("target"), // targetHash
            keccak256("preClaimOps"), // preClaimOpsHash
            keccak256("targetOps"), // targetOpsHash
            qualificationData // qualification data
        );
    }

    /// @notice Create ParamRules for checking function selectors in encoded ops
    function _createSelectorParamRules() private pure returns (ParamRules memory) {
        // Create a rule that checks the function selector in abi.encode(to, value, data) format
        // The selector is at position 96 in the encoded data (32+32+32 for to,value,dataLength)
        ParamRule[] memory rules = new ParamRule[](1);
        rules[0] = ParamRule({
            condition: ParamCondition.EQUAL,
            offset: 128, // Direct offset to function selector position
            length: 4, // Extract only 4 bytes for selector
            ref: bytes32(bytes4(keccak256("allowedFunction(uint256)"))) // Convert 4-byte selector
                // to bytes32
         });

        // Create a simple expression tree with one rule node
        uint256[] memory packedNodes = new uint256[](1);
        packedNodes[0] = ArgPolicyTreeLib.createRuleNode(0);

        return ParamRules({ rootNodeIndex: 0, rules: rules, packedNodes: packedNodes });
    }

    /// @notice Create ParamRules for checking qualification data
    function _createQualificationParamRules() private pure returns (ParamRules memory) {
        // Create a rule that checks the first parameter in qualification data
        // Qualification format: [dataLength(32)][typehash(32)][actualData...]
        // So first parameter starts at offset 64
        ParamRule[] memory rules = new ParamRule[](1);
        rules[0] = ParamRule({
            condition: ParamCondition.EQUAL,
            offset: 0, // Direct offset to first parameter position
            length: 0, // Use default 32 bytes for parameter
            ref: bytes32(uint256(0x1234567890123456789012345678901234567890123456789012345678901234))
        });

        // Create a simple expression tree with one rule node
        uint256[] memory packedNodes = new uint256[](1);
        packedNodes[0] = ArgPolicyTreeLib.createRuleNode(0);

        return ParamRules({ rootNodeIndex: 0, rules: rules, packedNodes: packedNodes });
    }

    /// @notice Create Lock struct data
    function _createLockData(address token, uint256 amount) private pure returns (bytes memory) {
        bytes12 lockTag = bytes12("test_lock");
        return abi.encodePacked(lockTag, token, amount);
    }

    /// @notice Create mandate data with custom targetOpsHash
    function _createMandateData(bytes32 targetOpsHash) private pure returns (bytes memory) {
        return abi.encodePacked(
            keccak256("target"), // targetHash
            keccak256("preClaimOps"), // preClaimOpsHash
            targetOpsHash, // targetOpsHash (custom)
            keccak256("qualification") // qualificationHash
        );
    }

    /// @notice Create mandate data for tokenIn tests
    function _createMandateData() private pure returns (bytes memory) {
        return abi.encodePacked(
            keccak256("target"), // targetHash
            keccak256("preClaimOps"), // preClaimOpsHash
            keccak256("targetOps"), // targetOpsHash
            keccak256("qualification") // qualificationHash
        );
    }

    /// @notice Create the compact header (sponsor + nonce + expires + otherElements)
    function _createCompactHeader() private view returns (bytes memory) {
        return abi.encodePacked(
            address(0x1234567890123456789012345678901234567890), // sponsor
            uint256(1), // nonce
            uint256(block.timestamp + 3600), // expires
            uint256(0) // otherElements length
        );
    }

    /// @notice Create the element header (arbiter + reserved + chainId)
    function _createElementHeader() private pure returns (bytes memory) {
        return abi.encodePacked(
            address(0x9876543210987654321098765432109876543210), // arbiter
            bytes12(0), // reserved
            uint256(1) // chainId
        );
    }

    /// @notice Create the target data (recipient + reserved + targetChain + fillExpires +
    /// claimHashProofer + tokenOut)
    function _createTargetData(
        address token,
        uint256 amount,
        uint256 targetChainId
    )
        private
        returns (bytes memory)
    {
        address recipient = makeAddr("recipient");
        return abi.encodePacked(
            recipient, // recipient (20 bytes)
            bytes12(0), // reserved (12 bytes)
            targetChainId, // targetChain (32 bytes)
            uint256(block.timestamp + 7200), // fillExpires (32 bytes)
            address(0xABcdEFABcdEFabcdEfAbCdefabcdeFABcDEFabCD), // claimHashProofer (20 bytes)
            bytes12(0), // reserved (12 bytes)
            uint256(1), // tokenOut length (32 bytes)
            token, // token address (20 bytes)
            amount // token amount (32 bytes)
        );
    }

    /// @notice Create the mandate footer (preClaimOps + targetOps + qualification hashes)
    function _createMandateFooter() private pure returns (bytes memory) {
        return abi.encodePacked(
            keccak256("preClaimOps"), // preClaimOpsHash
            keccak256("targetOps"), // targetOpsHash
            keccak256("qualification") // qualificationHash
        );
    }

    /// @notice Create a simple ParamRules structure for testing
    function _createSimpleParamRules() private pure returns (ParamRules memory) {
        // Create a simple rule that checks if first parameter equals specific value
        ParamRule[] memory rules = new ParamRule[](1);
        rules[0] = ParamRule({
            condition: ParamCondition.EQUAL,
            offset: 0, // Check first parameter (to)
            length: 0, // Use default 32 bytes for parameter
            ref: bytes32(uint256(uint160(0x1234567890123456789012345678901234567890)))
        });

        // Create a simple expression tree with one rule node
        uint256[] memory packedNodes = new uint256[](1);
        packedNodes[0] = ArgPolicyTreeLib.createRuleNode(0); // Simple rule node referencing rule 0

        return ParamRules({ rootNodeIndex: 0, rules: rules, packedNodes: packedNodes });
    }

    /// @notice Helper function to initialize policy with tokenOut condition
    function _initializePolicyWithTokenOut(
        address token,
        uint128 minAmount,
        uint128 maxAmount,
        uint256 targetChainId
    )
        internal
    {
        // Create policy config with only CHECK_TOKEN_OUT enabled (bit 4)
        uint8 conditionsBitmap = 16; // Binary: 00010000

        // Create tokenOut configuration
        bytes memory initData = abi.encodePacked(
            conditionsBitmap,
            uint256(1), // tokenOutConfigs count
            targetChainId, // targetChainId
            token, // token address (20 bytes)
            minAmount, // minAmount (16 bytes)
            maxAmount // maxAmount (16 bytes)
        );

        // Initialize the policy
        multiChainClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    /// @notice Helper function to initialize policy with qualification condition
    function _initializePolicyWithQualification() internal {
        // Create policy config with only CHECK_QUALIFICATIONS enabled (bit 2)
        uint8 conditionsBitmap = 2; // Binary: 00000010

        // Create qualification configuration with parameter validation rules
        ParamRules memory rules = _createQualificationParamRules();
        bytes memory rulesData = _encodeParamRules(rules);
        bytes32 typehash = keccak256("TestQualification(uint256 value)");

        bytes memory initData = abi.encodePacked(conditionsBitmap, typehash, rulesData);

        // Initialize the policy
        multiChainClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    /// @notice Helper to encode ParamRules for initialization
    function _encodeParamRules(ParamRules memory rules) private pure returns (bytes memory) {
        bytes memory result = abi.encodePacked(rules.rootNodeIndex, uint256(rules.rules.length));

        // Encode each rule
        for (uint256 i = 0; i < rules.rules.length; i++) {
            result = abi.encodePacked(
                result,
                uint8(rules.rules[i].condition),
                rules.rules[i].offset,
                rules.rules[i].length,
                rules.rules[i].ref
            );
        }

        // Encode packed nodes
        for (uint256 i = 0; i < rules.packedNodes.length; i++) {
            result = abi.encodePacked(result, rules.packedNodes[i]);
        }

        return result;
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

    /// @notice Helper function to initialize policy with tokenIn condition
    function _initializePolicyWithTokenIn(
        address token,
        uint128 minAmount,
        uint128 maxAmount
    )
        internal
    {
        // Create policy config with only CHECK_TOKEN_IN enabled (bit 3)
        uint8 conditionsBitmap = 8; // Binary: 00001000

        // Create tokenIn configuration
        bytes memory initData = abi.encodePacked(
            conditionsBitmap,
            uint256(1), // tokenInConfigs count
            uint256(1), // chainId
            token, // token address (20 bytes)
            minAmount, // minAmount (16 bytes)
            maxAmount // maxAmount (16 bytes)
        );

        // Initialize the policy
        multiChainClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    /// @notice Helper function to compute the expected hash for the MultiChainCompact using proper
    /// EIP712 hashing
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

        // Hash the mandate using proper EIP712 hashing
        bytes32 mandateHash =
            HashLib.hashMandate(targetHash, preClaimOpsHash, targetOpsHash, qualificationHash);

        // Hash the element using proper EIP712 hashing
        bytes32 notarizedElementHash =
            HashLib.hashElement(arbiter, chainId, commitmentsHash, mandateHash);

        // Create empty otherElements array
        bytes32[] memory otherElements = new bytes32[](0);

        // Hash the compact using proper EIP712 hashing
        return HashLib.hashCompact(sponsor, nonce, expires, notarizedElementHash, otherElements);
    }

    /// @notice Helper function to compute the expected hash for MultiChainCompact with tokenOut
    /// data
    function computeExpectedHashWithTokenOut(bytes calldata compactData)
        public
        pure
        returns (bytes32)
    {
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

        // Parse target data
        address recipient = address(bytes20(compactData[offset:offset + 20]));
        offset += 32; // Skip recipient + reserved space (20 + 12 = 32)
        uint256 targetChain = uint256(bytes32(compactData[offset:offset + 32]));
        offset += 32;
        uint256 fillExpires = uint256(bytes32(compactData[offset:offset + 32]));
        offset += 32;
        address claimHashProofer = address(bytes20(compactData[offset:offset + 20]));
        offset += 32; // Skip claimHashProofer + reserved space (20 + 12 = 32)

        // Parse tokenOut (Token structs)
        uint256 tokenOutLength = uint256(bytes32(compactData[offset:offset + 32]));
        offset += 32;

        // Create Token structs array and parse the data
        Token[] memory tokens = new Token[](tokenOutLength);
        for (uint256 i = 0; i < tokenOutLength; i++) {
            tokens[i] = Token({
                token: address(bytes20(compactData[offset:offset + 20])),
                amount: uint256(bytes32(compactData[offset + 20:offset + 52]))
            });
            offset += 52; // Each Token struct is 52 bytes (20 + 32)
        }

        // Hash the tokenOut using proper EIP712 hashing
        bytes32 tokenOutHash = HashLib.hashTokenOut(tokens);

        // Hash the target using proper EIP712 hashing
        bytes32 targetHash =
            HashLib.hashTarget(recipient, tokenOutHash, targetChain, fillExpires, claimHashProofer);

        // Continue parsing the rest of the data
        bytes32 preClaimOpsHash = bytes32(compactData[offset:offset + 32]);
        offset += 32;
        bytes32 targetOpsHash = bytes32(compactData[offset:offset + 32]);
        offset += 32;
        bytes32 qualificationHash = bytes32(compactData[offset:offset + 32]);

        // Hash the mandate using proper EIP712 hashing
        bytes32 mandateHash =
            HashLib.hashMandate(targetHash, preClaimOpsHash, targetOpsHash, qualificationHash);

        // Hash the element using proper EIP712 hashing
        bytes32 notarizedElementHash =
            HashLib.hashElement(arbiter, chainId, commitmentsHash, mandateHash);

        // Create empty otherElements array
        bytes32[] memory otherElements = new bytes32[](0);

        // Hash the compact using proper EIP712 hashing
        return HashLib.hashCompact(sponsor, nonce, expires, notarizedElementHash, otherElements);
    }

    /// @notice Helper function to compute the expected hash for MultiChainCompact with tokenIn data
    function computeExpectedHashWithTokenIn(bytes calldata compactData)
        public
        pure
        returns (bytes32)
    {
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

        // Parse commitments (Lock structs)
        uint256 commitmentsLength = uint256(bytes32(compactData[offset:offset + 32]));
        offset += 32;

        // Create Lock structs array and parse the data
        Lock[] memory locks = new Lock[](commitmentsLength);
        for (uint256 i = 0; i < commitmentsLength; i++) {
            locks[i] = Lock({
                lockTag: bytes12(compactData[offset:offset + 12]),
                token: address(bytes20(compactData[offset + 12:offset + 32])),
                amount: uint256(bytes32(compactData[offset + 32:offset + 64]))
            });
            offset += 64; // Each Lock struct is 64 bytes (12 + 20 + 32)
        }

        // Hash the commitments using proper EIP712 hashing
        bytes32 commitmentsHash = HashLib.hashCommitments(locks);

        // Continue parsing the rest of the data
        bytes32 targetHash = bytes32(compactData[offset:offset + 32]);
        offset += 32;
        bytes32 preClaimOpsHash = bytes32(compactData[offset:offset + 32]);
        offset += 32;
        bytes32 targetOpsHash = bytes32(compactData[offset:offset + 32]);
        offset += 32;
        bytes32 qualificationHash = bytes32(compactData[offset:offset + 32]);

        // Hash the mandate using proper EIP712 hashing
        bytes32 mandateHash =
            HashLib.hashMandate(targetHash, preClaimOpsHash, targetOpsHash, qualificationHash);

        // Hash the element using proper EIP712 hashing
        bytes32 notarizedElementHash =
            HashLib.hashElement(arbiter, chainId, commitmentsHash, mandateHash);

        // Create empty otherElements array
        bytes32[] memory otherElements = new bytes32[](0);

        // Hash the compact using proper EIP712 hashing
        return HashLib.hashCompact(sponsor, nonce, expires, notarizedElementHash, otherElements);
    }

    /// @notice Helper function to compute expected hash with qualification
    function computeExpectedHashWithQualification(bytes calldata compactData)
        public
        pure
        returns (bytes32)
    {
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

        // Parse qualification data and hash it
        bytes32 qualificationHash = _parseAndHashQualification(compactData, offset);

        // Hash the mandate using proper EIP712 hashing
        bytes32 mandateHash =
            HashLib.hashMandate(targetHash, preClaimOpsHash, targetOpsHash, qualificationHash);

        // Hash the element using proper EIP712 hashing
        bytes32 notarizedElementHash =
            HashLib.hashElement(arbiter, chainId, commitmentsHash, mandateHash);

        // Create empty otherElements array
        bytes32[] memory otherElements = new bytes32[](0);

        // Hash the compact using proper EIP712 hashing
        return HashLib.hashCompact(sponsor, nonce, expires, notarizedElementHash, otherElements);
    }

    /// @notice Parse and hash qualification data
    function _parseAndHashQualification(
        bytes calldata data,
        uint256 offset
    )
        private
        pure
        returns (bytes32)
    {
        uint256 dataLength = uint256(bytes32(data[offset:offset + 32]));
        return HashLib.hashQualification(data[offset + 64:offset + 64 + dataLength]); // Skip length
            // + typehash, just hash the data
    }
}
