// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import {
    CompactClaimPolicy_Unit_Test
} from "@test/unit/policies/claim/CompactClaimPolicy/compactClaimPolicy.t.sol";

// Libraries
import { EIP712TypeHashLib } from "@compact-utils/types/EIP712TypeHashLib.sol";
import { DomainLib } from "@the-compact/lib/DomainLib.sol";
import { EfficientHashLib } from "@solady/utils/EfficientHashLib.sol";
import { Bytes32ArrayLib } from "@rhinestone/compact-utils/src/common/Bytes32ArrayLib.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import { ParamRules, ParamRule } from "@policies/claim/base/types/BaseDataTypes.sol";
import { ParamCondition } from "@smartsessions/external/policies/ArgPolicy/ArgPolicy.sol";
import {
    MODE_SKIP,
    MODE_CHECK_STORAGE,
    MODE_CHECK_CATCHALL,
    FIELD_ARBITER,
    FIELD_EXPIRY,
    FIELD_TOKEN_IN,
    FIELD_RECIPIENT,
    FIELD_FILL_EXPIRY,
    FIELD_TOKEN_OUT,
    FIELD_ORIGIN_OPS,
    FIELD_DEST_OPS,
    FIELD_QUALIFICATION
} from "@policies/claim/base/types/BaseDataTypes.sol";
import { Constants } from "@compact-utils/types/Constants.sol";

// Utils
import { console2 } from "forge-std/console2.sol";

contract CompactClaimPolicy_check1271SignedAction_Test is CompactClaimPolicy_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using EfficientHashLib for bytes32[];
    using Bytes32ArrayLib for bytes32[];

    /*//////////////////////////////////////////////////////////////
                                 VARIABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice Test account
    address internal testAccount;

    /// @notice Test config ID
    ConfigId internal testConfigId;

    /// @notice Test domain separator
    bytes32 internal testDomainSeparator =
        0x1234567890123456789012345678901234567890123456789012345678901234;

    /*//////////////////////////////////////////////////////////////
                                   SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        super.setUp();

        testAccount = makeAddr("testAccount");
        testConfigId = ConfigId.wrap(bytes32(uint256(1)));
    }

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    //-------------------------------------
    // 1) ARBITER
    //-------------------------------------

    /// @notice Test check1271SignedAction with arbiter check - should pass when arbiter matches
    function test_check1271SignedAction_arbiter_valid_shouldPass() public {
        address testArbiter = makeAddr("testArbiter");

        // Initialize policy with arbiter check
        _initializePolicyWithArbiter(testArbiter);

        // Create Compact data with matching arbiter
        bytes memory compactData = _createCompactDataWithArbiter(testArbiter);

        // Compute expected hash
        bytes32 expectedHash = this.computeExpectedHash(compactData);

        // Check the action
        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "Action with valid arbiter should be allowed");
    }

    /// @notice Test check1271SignedAction with arbiter check - should fail when arbiter doesn't
    /// match
    function test_check1271SignedAction_arbiter_invalid_shouldFail() public {
        address expectedArbiter = makeAddr("expectedArbiter");
        address wrongArbiter = makeAddr("wrongArbiter");

        // Initialize policy with expected arbiter
        _initializePolicyWithArbiter(expectedArbiter);

        // Create Compact data with wrong arbiter
        bytes memory compactData = _createCompactDataWithArbiter(wrongArbiter);

        // Compute expected hash
        bytes32 expectedHash = this.computeExpectedHash(compactData);

        // Check the action
        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertFalse(result, "Action with wrong arbiter should be rejected");
    }

    //-------------------------------------
    // 2) CLAIM EXPIRES
    //-------------------------------------

    /// @notice Test check1271SignedAction with claim expires check - should pass when in range
    function test_check1271SignedAction_claimExpires_valid_shouldPass() public {
        uint128 minExpires = uint128(block.timestamp + 1000);
        uint128 maxExpires = uint128(block.timestamp + 10_000);
        uint256 testExpires = block.timestamp + 5000; // Within range

        // Initialize policy with claim expires check
        _initializePolicyWithClaimExpires(minExpires, maxExpires);

        // Create Compact data with valid expires
        bytes memory compactData = _createCompactDataWithExpires(testExpires);

        // Compute expected hash
        bytes32 expectedHash = this.computeExpectedHash(compactData);

        // Check the action
        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "Action with valid claim expires should be allowed");
    }

    /// @notice Test check1271SignedAction with claim expires check - should fail when below min
    function test_check1271SignedAction_claimExpires_belowMin_shouldFail() public {
        uint128 minExpires = uint128(block.timestamp + 5000);
        uint128 maxExpires = uint128(block.timestamp + 10_000);
        uint256 testExpires = block.timestamp + 1000; // Below min

        // Initialize policy with claim expires check
        _initializePolicyWithClaimExpires(minExpires, maxExpires);

        // Create Compact data with expires below min
        bytes memory compactData = _createCompactDataWithExpires(testExpires);

        // Compute expected hash
        bytes32 expectedHash = this.computeExpectedHash(compactData);

        // Check the action
        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertFalse(result, "Action with expires below min should be rejected");
    }

    //-------------------------------------
    // 3) TOKEN IN
    //-------------------------------------

    /// @notice Test check1271SignedAction with tokenIn check - should pass when valid
    function test_check1271SignedAction_tokenIn_valid_shouldPass() public {
        address testToken = makeAddr("testToken");
        bytes12 testLockTag = bytes12("test_lock");
        uint256 elementIndex = 0;

        // Initialize policy with tokenIn check
        _initializePolicyWithTokenIn(testToken, testLockTag, block.chainid);

        // Create Compact data with valid tokenIn
        bytes memory compactData =
            _createCompactDataWithTokenIn(testToken, testLockTag, 1000, elementIndex);

        // Compute expected hash
        bytes32 expectedHash = this.computeExpectedHashWithTokenIn(compactData);

        // Check the action
        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "Action with valid tokenIn should be allowed");
    }

    //-------------------------------------
    // 4) RECIPIENT
    //-------------------------------------

    /// @notice Test check1271SignedAction with recipient check - should pass when valid
    function test_check1271SignedAction_recipient_valid_shouldPass() public {
        address testRecipient = makeAddr("testRecipient");
        uint256 targetChainId = 137; // Polygon

        // Initialize policy with recipient check
        _initializePolicyWithRecipient(testRecipient, targetChainId);

        // Create Compact data with valid recipient
        bytes memory compactData = _createCompactDataWithRecipient(testRecipient, targetChainId);

        // Compute expected hash
        bytes32 expectedHash = this.computeExpectedHashWithTarget(compactData);

        // Check the action
        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "Action with valid recipient should be allowed");
    }

    //-------------------------------------
    // 5) ORIGIN OPS
    //-------------------------------------

    /// @notice Test check1271SignedAction with originOps check - should pass when required and
    /// present
    function test_check1271SignedAction_originOps_requiredAndPresent_shouldPass() public {
        uint256 elementIndex = 0;
        bool requireOriginOps = true;

        // Initialize policy requiring originOps
        _initializePolicyWithOriginOps(requireOriginOps, block.chainid);

        // Create Compact data with originOps present
        bytes32 nonEmptyOpsHash = keccak256("some ops");
        bytes memory compactData = _createCompactDataWithOriginOps(nonEmptyOpsHash, elementIndex);

        // Compute expected hash
        bytes32 expectedHash = this.computeExpectedHash(compactData);

        // Check the action
        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "Action with required originOps present should be allowed");
    }

    /// @notice Test check1271SignedAction with originOps check - should fail when required but
    /// missing
    function test_check1271SignedAction_originOps_requiredButMissing_shouldFail() public {
        uint256 elementIndex = 0;
        bool requireOriginOps = true;

        // Initialize policy requiring originOps
        _initializePolicyWithOriginOps(requireOriginOps, block.chainid);

        // Create Compact data with NO_OPS
        bytes memory compactData = _createCompactDataWithOriginOps(Constants.NO_OPS, elementIndex);

        // Compute expected hash
        bytes32 expectedHash = this.computeExpectedHash(compactData);

        // Check the action
        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertFalse(result, "Action with required but missing originOps should be rejected");
    }

    //-------------------------------------
    // 6) FILL EXPIRY
    //-------------------------------------

    /// @notice Test check1271SignedAction with fillExpiry check - should pass when in range
    function test_check1271SignedAction_fillExpiry_valid_shouldPass() public {
        uint128 minExpiry = uint128(block.timestamp + 1000);
        uint128 maxExpiry = uint128(block.timestamp + 10_000);
        uint256 testExpiry = block.timestamp + 5000; // Within range
        uint256 targetChainId = 137;

        // Initialize policy with fillExpiry check
        _initializePolicyWithFillExpiry(minExpiry, maxExpiry, targetChainId);

        // Create Compact data with valid fillExpiry
        bytes memory compactData = _createCompactDataWithFillExpiry(testExpiry, targetChainId);

        // Compute expected hash
        bytes32 expectedHash = this.computeExpectedHashWithTarget(compactData);

        // Check the action
        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "Action with valid fillExpiry should be allowed");
    }

    /// @notice Test check1271SignedAction with fillExpiry check - should fail when below min
    function test_check1271SignedAction_fillExpiry_belowMin_shouldFail() public {
        uint128 minExpiry = uint128(block.timestamp + 5000);
        uint128 maxExpiry = uint128(block.timestamp + 10_000);
        uint256 testExpiry = block.timestamp + 1000; // Below min
        uint256 targetChainId = 137;

        // Initialize policy with fillExpiry check
        _initializePolicyWithFillExpiry(minExpiry, maxExpiry, targetChainId);

        // Create Compact data with fillExpiry below min
        bytes memory compactData = _createCompactDataWithFillExpiry(testExpiry, targetChainId);

        // Compute expected hash
        bytes32 expectedHash = this.computeExpectedHashWithTarget(compactData);

        // Check the action
        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertFalse(result, "Action with fillExpiry below min should be rejected");
    }

    /// @notice Test check1271SignedAction with fillExpiry check - should fail when above max
    function test_check1271SignedAction_fillExpiry_aboveMax_shouldFail() public {
        uint128 minExpiry = uint128(block.timestamp + 1000);
        uint128 maxExpiry = uint128(block.timestamp + 5000);
        uint256 testExpiry = block.timestamp + 10_000; // Above max
        uint256 targetChainId = 137;

        // Initialize policy with fillExpiry check
        _initializePolicyWithFillExpiry(minExpiry, maxExpiry, targetChainId);

        // Create Compact data with fillExpiry above max
        bytes memory compactData = _createCompactDataWithFillExpiry(testExpiry, targetChainId);

        // Compute expected hash
        bytes32 expectedHash = this.computeExpectedHashWithTarget(compactData);

        // Check the action
        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertFalse(result, "Action with fillExpiry above max should be rejected");
    }

    //-------------------------------------
    // 7) TOKEN OUT
    //-------------------------------------

    /// @notice Test check1271SignedAction with tokenOut check - should pass when valid
    function test_check1271SignedAction_tokenOut_valid_shouldPass() public {
        address testToken = makeAddr("testToken");
        uint256 targetChainId = 137;

        // Initialize policy with tokenOut check
        _initializePolicyWithTokenOut(testToken, targetChainId);

        // Create Compact data with valid tokenOut
        bytes memory compactData = _createCompactDataWithTokenOut(testToken, 1000, targetChainId);

        // Compute expected hash
        bytes32 expectedHash = this.computeExpectedHashWithTokenOut(compactData);

        // Check the action
        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "Action with valid tokenOut should be allowed");
    }

    /// @notice Test check1271SignedAction with tokenOut check - should fail when token invalid
    function test_check1271SignedAction_tokenOut_invalidToken_shouldFail() public {
        address expectedToken = makeAddr("expectedToken");
        address wrongToken = makeAddr("wrongToken");
        uint256 targetChainId = 137;

        // Initialize policy with tokenOut check for expectedToken
        _initializePolicyWithTokenOut(expectedToken, targetChainId);

        // Create Compact data with wrong token
        bytes memory compactData = _createCompactDataWithTokenOut(wrongToken, 1000, targetChainId);

        // Compute expected hash
        bytes32 expectedHash = this.computeExpectedHashWithTokenOut(compactData);

        // Check the action
        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertFalse(result, "Action with invalid tokenOut should be rejected");
    }

    //-------------------------------------
    // 8) DEST OPS
    //-------------------------------------

    /// @notice Test check1271SignedAction with destOps check - should pass when required and
    /// present
    function test_check1271SignedAction_destOps_requiredAndPresent_shouldPass() public {
        uint256 targetChainId = 137;
        bool requireDestOps = true;

        // Initialize policy requiring destOps
        _initializePolicyWithDestOps(requireDestOps, targetChainId);

        // Create Compact data with destOps present
        bytes32 nonEmptyOpsHash = keccak256("some dest ops");
        bytes memory compactData = _createCompactDataWithDestOps(nonEmptyOpsHash, targetChainId);

        // Compute expected hash
        bytes32 expectedHash = this.computeExpectedHash(compactData);

        // Check the action
        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "Action with required destOps present should be allowed");
    }

    /// @notice Test check1271SignedAction with destOps check - should fail when required but
    /// missing
    function test_check1271SignedAction_destOps_requiredButMissing_shouldFail() public {
        uint256 targetChainId = 137;
        bool requireDestOps = true;

        // Initialize policy requiring destOps
        _initializePolicyWithDestOps(requireDestOps, targetChainId);

        // Create Compact data with NO_OPS
        bytes memory compactData = _createCompactDataWithDestOps(Constants.NO_OPS, targetChainId);

        // Compute expected hash
        bytes32 expectedHash = this.computeExpectedHash(compactData);

        // Check the action
        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertFalse(result, "Action with required but missing destOps should be rejected");
    }

    //-------------------------------------
    // 9) QUALIFICATION
    //-------------------------------------

    /// @notice Test check1271SignedAction with qualification check - should pass when valid
    function test_check1271SignedAction_qualification_valid_shouldPass() public {
        uint256 elementIndex = 0;
        address arbiter = makeAddr("qualificationArbiter");

        // Create simple rule: bytes[0:32] EQUAL to 0x123...
        bytes32 expectedValue = bytes32(uint256(0x123));
        ParamRule[] memory rules = new ParamRule[](1);
        rules[0] = ParamRule({
            condition: ParamCondition.EQUAL, offset: 0, length: 32, ref: expectedValue
        });

        // Create simple expression tree: just check rule 0
        uint256[] memory packedNodes = new uint256[](1);
        packedNodes[0] = uint256(0) | (uint256(0) << 8); // NODE_TYPE_RULE, ruleIndex=0

        ParamRules memory paramRules =
            ParamRules({ rootNodeIndex: 0, rules: rules, packedNodes: packedNodes });

        // Initialize policy with qualification check
        _initializePolicyWithQualification(arbiter, paramRules, block.chainid);

        // Create qualification data that matches the rule
        bytes memory qualData = abi.encodePacked(expectedValue);
        bytes memory compactData = _createCompactDataWithQualification(
            arbiter,
            qualData,
            elementIndex // element index
        );

        // Compute expected hash
        bytes32 expectedHash = this.computeExpectedHashWithQualification(compactData);

        // Check the action
        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "Action with valid qualification should be allowed");
    }

    /// @notice Test check1271SignedAction with qualification check - should fail when invalid
    function test_check1271SignedAction_qualification_invalid_shouldFail() public {
        uint256 elementIndex = 0;
        address arbiter = makeAddr("qualificationArbiter");

        // Create simple rule: bytes[0:32] EQUAL to 0x123...
        bytes32 expectedValue = bytes32(uint256(0x123));
        ParamRule[] memory rules = new ParamRule[](1);
        rules[0] = ParamRule({
            condition: ParamCondition.EQUAL, offset: 0, length: 32, ref: expectedValue
        });

        // Create simple expression tree: just check rule 0
        uint256[] memory packedNodes = new uint256[](1);
        packedNodes[0] = uint256(0) | (uint256(0) << 8); // NODE_TYPE_RULE, ruleIndex=0

        ParamRules memory paramRules =
            ParamRules({ rootNodeIndex: 0, rules: rules, packedNodes: packedNodes });

        // Initialize policy with qualification check
        _initializePolicyWithQualification(arbiter, paramRules, block.chainid);

        // Create qualification data that DOESN'T match the rule
        bytes32 wrongValue = bytes32(uint256(0x456));
        bytes memory qualData = abi.encodePacked(wrongValue);
        bytes memory compactData =
            _createCompactDataWithQualification(arbiter, qualData, elementIndex);

        // Compute expected hash
        bytes32 expectedHash = this.computeExpectedHashWithQualification(compactData);

        // Check the action
        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertFalse(result, "Action with invalid qualification should be rejected");
    }

    /*//////////////////////////////////////////////////////////////
                                 HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Helper to create mode config with specific field mode
    function _createModeConfig(uint8 fieldId, uint8 mode) internal pure returns (uint32) {
        return uint32(mode) << (fieldId * 2);
    }

    /// @notice Initialize policy with arbiter check
    function _initializePolicyWithArbiter(address arbiter) internal {
        uint32 modeConfig = _createModeConfig(FIELD_ARBITER, MODE_CHECK_STORAGE);
        bytes memory initData = abi.encodePacked(modeConfig, uint256(1), arbiter);

        compactClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    /// @notice Initialize policy with claim expires check
    function _initializePolicyWithClaimExpires(uint128 min, uint128 max) internal {
        uint32 modeConfig = _createModeConfig(FIELD_EXPIRY, MODE_CHECK_STORAGE);
        bytes memory initData = abi.encodePacked(
            modeConfig,
            uint256(min) | (uint256(max) << 128) // packed uint128
        );

        compactClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    /// @notice Initialize policy with tokenIn check
    /// @notice Initialize policy with tokenIn check
    function _initializePolicyWithTokenIn(
        address token,
        bytes12 lockTag,
        uint256 chainId
    )
        internal
    {
        uint32 modeConfig = _createModeConfig(FIELD_TOKEN_IN, MODE_CHECK_STORAGE);

        // Create Compact ID in native format: [lockTag HIGH | token LOW]
        uint256 compactId = (uint256(uint96(lockTag)) << 160) | uint256(uint160(token));

        bytes memory initData = abi.encodePacked(
            modeConfig,
            uint256(1), // count
            uint256(chainId),
            compactId // pass the full Compact ID directly
        );

        compactClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    /// @notice Initialize policy with recipient check
    function _initializePolicyWithRecipient(
        address recipient,
        uint256 targetChainId
    )
        internal
    {
        uint32 modeConfig = _createModeConfig(FIELD_RECIPIENT, MODE_CHECK_STORAGE);
        bytes memory initData = abi.encodePacked(
            modeConfig,
            uint256(1), // count
            targetChainId,
            recipient
        );

        compactClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    /// @notice Initialize policy with originOps check
    function _initializePolicyWithOriginOps(bool required, uint256 chainId) internal {
        uint32 modeConfig = _createModeConfig(FIELD_ORIGIN_OPS, MODE_CHECK_STORAGE);
        bytes memory initData = abi.encodePacked(
            modeConfig,
            uint256(1), // count
            chainId,
            uint8(required ? 1 : 0)
        );

        compactClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    /// @notice Create Compact data with specific arbiter
    function _createCompactDataWithArbiter(address arbiter) internal view returns (bytes memory) {
        bytes memory header = _createCompactHeader();
        bytes memory elementHeader = _createElementHeader(arbiter, 0);
        bytes memory mandateData = _createMandateData();

        return abi.encodePacked(header, elementHeader, keccak256("commitments"), mandateData);
    }

    /// @notice Create Compact data with specific expires
    function _createCompactDataWithExpires(uint256 expires) internal returns (bytes memory) {
        bytes memory header = abi.encodePacked(
            uint256(1), // nonce
            expires,
            uint256(0) // otherElements length
        );

        bytes memory elementHeader = _createElementHeader(makeAddr("arbiter"), 0);
        bytes memory mandateData = _createMandateData();

        return abi.encodePacked(header, elementHeader, keccak256("commitments"), mandateData);
    }

    /// @notice Create Compact data with tokenIn
    function _createCompactDataWithTokenIn(
        address token,
        bytes12 lockTag,
        uint256 amount,
        uint256 elementIndex
    )
        internal
        returns (bytes memory)
    {
        bytes memory header = _createCompactHeader();
        bytes memory elementHeader = _createElementHeader(makeAddr("arbiter"), elementIndex);

        // Create tokenIn data: length + packed token/lockTag + amount
        uint256 tokenData = (uint256(uint96(lockTag)) << 160) | uint256(uint160(token));
        bytes memory tokenInData = abi.encodePacked(
            uint256(1), // length
            tokenData,
            amount
        );

        bytes memory mandateData = _createMandateData();

        return abi.encodePacked(header, elementHeader, tokenInData, mandateData);
    }

    /// @notice Create Compact data with recipient
    function _createCompactDataWithRecipient(
        address recipient,
        uint256 targetChainId
    )
        internal
        returns (bytes memory)
    {
        bytes memory header = _createCompactHeader();
        bytes memory elementHeader = _createElementHeader(makeAddr("arbiter"), 0);

        // Create target data WITHOUT tokenOut validation (so use hash, not length)
        bytes memory targetData = abi.encodePacked(
            recipient,
            bytes12(0), // reserved
            targetChainId,
            uint256(block.timestamp + 7200), // fillExpiry
            Constants.EMPTY_TOKEN_OUT_HASH // tokenOutHash
        );

        bytes memory mandateFooter = _createMandateFooter();

        return abi.encodePacked(
            header, elementHeader, keccak256("commitments"), targetData, mandateFooter
        );
    }

    /// @notice Create Compact data with originOps
    function _createCompactDataWithOriginOps(
        bytes32 originOpsHash,
        uint256 elementIndex
    )
        internal
        returns (bytes memory)
    {
        bytes memory header = _createCompactHeader();
        bytes memory elementHeader = _createElementHeader(makeAddr("arbiter"), elementIndex);

        bytes memory mandateData = abi.encodePacked(
            keccak256("target"), // targetHash (32 bytes)
            uint256(1), // targetChainId (32 bytes)
            uint128(0), // minGas (16 bytes)
            originOpsHash, // originOpsHash (32 bytes)
            Constants.NO_OPS, // destOpsHash (32 bytes)
            keccak256("qualification") // qualificationHash (32 bytes)
        );

        return abi.encodePacked(header, elementHeader, keccak256("commitments"), mandateData);
    }

    /// @notice Create basic compact header
    function _createCompactHeader() private view returns (bytes memory) {
        return abi.encodePacked(
            uint256(1), // nonce
            uint256(block.timestamp + 3600), // expires
            uint256(0) // otherElements length
        );
    }

    /// @notice Create element header with arbiter and chainId
    function _createElementHeader(
        address arbiter,
        uint256 elementIndex
    )
        private
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            arbiter,
            bytes12(0), // reserved
            elementIndex
        );
    }

    /// @notice Create basic mandate data
    function _createMandateData() private pure returns (bytes memory) {
        return abi.encodePacked(
            keccak256("target"), // targetHash (32 bytes)
            uint256(1), // targetChainId (32 bytes)
            uint128(0), // minGas (16 bytes)
            Constants.NO_OPS, // originOpsHash (32 bytes)
            Constants.NO_OPS, // destOpsHash (32 bytes)
            keccak256("qualification") // qualificationHash (32 bytes)
        );
    }

    /// @notice Create mandate footer (for when target is expanded)
    function _createMandateFooter() private pure returns (bytes memory) {
        return abi.encodePacked(
            // NO targetChainId here! It's inside the target data
            uint128(0), // minGas (16 bytes)
            Constants.NO_OPS, // originOpsHash (32 bytes)
            Constants.NO_OPS, // destOpsHash (32 bytes)
            keccak256("qualification") // qualificationHash (32 bytes)
        );
    }

    /// @notice Compute expected hash for Compact
    function computeExpectedHash(bytes calldata compactData) external view returns (bytes32) {
        // Parse compact data
        uint256 nonce = uint256(bytes32(compactData[0:32]));
        uint256 expires = uint256(bytes32(compactData[32:64]));

        // Parse otherElements as calldata
        uint256 otherElementsLength = uint256(bytes32(compactData[64:96]));
        bytes32[] calldata otherElements;
        assembly {
            otherElements.offset := add(compactData.offset, 96)
            otherElements.length := otherElementsLength
        }
        uint256 offset = 96 + otherElementsLength * 32;

        // Parse element
        address arbiter = address(bytes20(compactData[offset:offset + 20]));
        offset += 32; // arbiter + reserved
        uint256 elementIndex = uint256(bytes32(compactData[offset:offset + 32]));
        offset += 32;
        bytes32 commitmentsHash = bytes32(compactData[offset:offset + 32]);
        offset += 32;

        // Parse mandate
        bytes32 targetHash = bytes32(compactData[offset:offset + 32]);
        offset += 32;
        offset += 32; // skip targetChainId
        uint128 minGas = uint128(bytes16(compactData[offset:offset + 16]));
        offset += 16;
        bytes32 originOpsHash = bytes32(compactData[offset:offset + 32]);
        offset += 32;
        bytes32 destOpsHash = bytes32(compactData[offset:offset + 32]);
        offset += 32;
        bytes32 qualificationHash = bytes32(compactData[offset:offset + 32]);

        // Hash mandate
        bytes32 mandateHash = EIP712TypeHashLib.hashMandateRaw(
            targetHash, minGas, originOpsHash, destOpsHash, qualificationHash
        );

        // Hash element
        bytes32 elementHash =
            EIP712TypeHashLib.hashElementRaw(arbiter, block.chainid, commitmentsHash, mandateHash);

        // Insert at index and hash
        bytes32 allElementsHash = otherElements.insertAtAndHash(elementIndex, elementHash);

        return EIP712TypeHashLib.hashCompact(testAccount, nonce, expires, allElementsHash);
    }

    /// @notice Compute expected hash when target is expanded (for recipient test)
    function computeExpectedHashWithTarget(bytes calldata compactData)
        external
        view
        returns (bytes32)
    {
        // Parse compact data
        uint256 nonce = uint256(bytes32(compactData[0:32]));
        uint256 expires = uint256(bytes32(compactData[32:64]));

        // Parse otherElements as calldata
        uint256 otherElementsLength = uint256(bytes32(compactData[64:96]));
        bytes32[] calldata otherElements;
        assembly {
            otherElements.offset := add(compactData.offset, 96)
            otherElements.length := otherElementsLength
        }
        uint256 offset = 96 + otherElementsLength * 32;

        // Parse element
        address arbiter = address(bytes20(compactData[offset:offset + 20]));
        offset += 32; // arbiter + reserved
        uint256 elementIndex = uint256(bytes32(compactData[offset:offset + 32]));
        offset += 32;
        bytes32 commitmentsHash = bytes32(compactData[offset:offset + 32]);
        offset += 32;

        // Parse TARGET (expanded!)
        address recipient = address(bytes20(compactData[offset:offset + 20]));
        offset += 32; // recipient + reserved
        uint256 targetChainId = uint256(bytes32(compactData[offset:offset + 32]));
        offset += 32;
        uint256 fillExpiry = uint256(bytes32(compactData[offset:offset + 32]));
        offset += 32;

        // Read tokenOut hash directly
        bytes32 tokenOutHash = bytes32(compactData[offset:offset + 32]);
        offset += 32;

        // Hash target
        bytes32 targetHash = EIP712TypeHashLib.hashTargetAttributesRaw(
            recipient, tokenOutHash, targetChainId, fillExpiry
        );

        // Parse mandate footer
        uint128 minGas = uint128(bytes16(compactData[offset:offset + 16]));
        offset += 16;
        bytes32 originOpsHash = bytes32(compactData[offset:offset + 32]);
        offset += 32;
        bytes32 destOpsHash = bytes32(compactData[offset:offset + 32]);
        offset += 32;
        bytes32 qualificationHash = bytes32(compactData[offset:offset + 32]);

        // Hash mandate
        bytes32 mandateHash = EIP712TypeHashLib.hashMandateRaw(
            targetHash, minGas, originOpsHash, destOpsHash, qualificationHash
        );

        // Hash element
        bytes32 elementHash =
            EIP712TypeHashLib.hashElementRaw(arbiter, block.chainid, commitmentsHash, mandateHash);

        // Insert at index and hash
        bytes32 allElementsHash = otherElements.insertAtAndHash(elementIndex, elementHash);

        return EIP712TypeHashLib.hashCompact(testAccount, nonce, expires, allElementsHash);
    }

    /// @notice Compute expected hash when tokenIn is expanded
    function computeExpectedHashWithTokenIn(bytes calldata compactData)
        external
        view
        returns (bytes32)
    {
        // Parse compact data
        uint256 nonce = uint256(bytes32(compactData[0:32]));
        uint256 expires = uint256(bytes32(compactData[32:64]));

        // Parse otherElements as calldata
        uint256 otherElementsLength = uint256(bytes32(compactData[64:96]));
        bytes32[] calldata otherElements;
        assembly {
            otherElements.offset := add(compactData.offset, 96)
            otherElements.length := otherElementsLength
        }
        uint256 offset = 96 + otherElementsLength * 32;

        // Parse element
        address arbiter = address(bytes20(compactData[offset:offset + 20]));
        offset += 32; // arbiter + reserved
        uint256 elementIndex = uint256(bytes32(compactData[offset:offset + 32]));
        offset += 32;

        // Parse tokenIn (expanded!)
        uint256 tokenInLength = uint256(bytes32(compactData[offset:offset + 32]));
        offset += 32;

        // Create calldata pointer to tokenIn
        uint256[2][] calldata tokenIn;
        assembly {
            tokenIn.offset := add(compactData.offset, offset)
            tokenIn.length := tokenInLength
        }

        // Hash tokenIn
        bytes32 commitmentsHash = EIP712TypeHashLib.hashTokenIn(tokenIn);
        offset += tokenInLength * 64;

        // Parse mandate
        bytes32 targetHash = bytes32(compactData[offset:offset + 32]);
        offset += 32;
        offset += 32; // skip targetChainId
        uint128 minGas = uint128(bytes16(compactData[offset:offset + 16]));
        offset += 16;
        bytes32 originOpsHash = bytes32(compactData[offset:offset + 32]);
        offset += 32;
        bytes32 destOpsHash = bytes32(compactData[offset:offset + 32]);
        offset += 32;
        bytes32 qualificationHash = bytes32(compactData[offset:offset + 32]);

        // Hash mandate
        bytes32 mandateHash = EIP712TypeHashLib.hashMandateRaw(
            targetHash, minGas, originOpsHash, destOpsHash, qualificationHash
        );

        // Hash element
        bytes32 elementHash =
            EIP712TypeHashLib.hashElementRaw(arbiter, block.chainid, commitmentsHash, mandateHash);

        // Insert at index and hash
        bytes32 allElementsHash = otherElements.insertAtAndHash(elementIndex, elementHash);

        return EIP712TypeHashLib.hashCompact(testAccount, nonce, expires, allElementsHash);
    }

    /// @notice Initialize policy with fillExpiry check
    function _initializePolicyWithFillExpiry(
        uint128 min,
        uint128 max,
        uint256 targetChainId
    )
        internal
    {
        uint32 modeConfig = _createModeConfig(FIELD_FILL_EXPIRY, MODE_CHECK_STORAGE);
        bytes memory initData = abi.encodePacked(
            modeConfig,
            uint256(1), // count
            targetChainId,
            uint256(min) | (uint256(max) << 128) // packed uint128
        );

        compactClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    /// @notice Initialize policy with tokenOut check
    function _initializePolicyWithTokenOut(address token, uint256 targetChainId) internal {
        uint32 modeConfig = _createModeConfig(FIELD_TOKEN_OUT, MODE_CHECK_STORAGE);
        bytes memory initData = abi.encodePacked(
            modeConfig,
            uint256(1), // count
            targetChainId,
            token
        );

        compactClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    /// @notice Initialize policy with destOps check
    function _initializePolicyWithDestOps(bool required, uint256 targetChainId) internal {
        uint32 modeConfig = _createModeConfig(FIELD_DEST_OPS, MODE_CHECK_STORAGE);
        bytes memory initData = abi.encodePacked(
            modeConfig,
            uint256(1), // count
            targetChainId,
            uint8(required ? 1 : 0)
        );

        compactClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    /// @notice Create Compact data with fillExpiry
    function _createCompactDataWithFillExpiry(
        uint256 fillExpiry,
        uint256 targetChainId
    )
        internal
        returns (bytes memory)
    {
        bytes memory header = _createCompactHeader();
        bytes memory elementHeader = _createElementHeader(makeAddr("arbiter"), 0);

        // Create target data with specific fillExpiry
        bytes memory targetData = abi.encodePacked(
            makeAddr("recipient"),
            bytes12(0), // reserved
            targetChainId,
            fillExpiry,
            Constants.EMPTY_TOKEN_OUT_HASH // tokenOutHash
        );

        bytes memory mandateFooter = _createMandateFooter();

        return abi.encodePacked(
            header, elementHeader, keccak256("commitments"), targetData, mandateFooter
        );
    }

    /// @notice Create Compact data with tokenOut
    function _createCompactDataWithTokenOut(
        address token,
        uint256 amount,
        uint256 targetChainId
    )
        internal
        returns (bytes memory)
    {
        bytes memory header = _createCompactHeader();
        bytes memory elementHeader = _createElementHeader(makeAddr("arbiter"), 0);

        // Create target data with tokenOut
        uint256 tokenData = uint256(uint160(token));
        bytes memory targetData = abi.encodePacked(
            makeAddr("recipient"),
            bytes12(0), // reserved
            targetChainId,
            uint256(block.timestamp + 7200), // fillExpiry
            uint256(1), // tokenOut length
            tokenData,
            amount
        );

        bytes memory mandateFooter = _createMandateFooter();

        return abi.encodePacked(
            header, elementHeader, keccak256("commitments"), targetData, mandateFooter
        );
    }

    /// @notice Create Compact data with destOps
    function _createCompactDataWithDestOps(
        bytes32 destOpsHash,
        uint256 targetChainId
    )
        internal
        returns (bytes memory)
    {
        bytes memory header = _createCompactHeader();
        bytes memory elementHeader = _createElementHeader(makeAddr("arbiter"), 0);

        bytes memory mandateData = abi.encodePacked(
            keccak256("target"), // targetHash (32 bytes)
            targetChainId, // targetChainId (32 bytes)
            uint128(0), // minGas (16 bytes)
            Constants.NO_OPS, // originOpsHash (32 bytes)
            destOpsHash, // destOpsHash (32 bytes)
            keccak256("qualification") // qualificationHash (32 bytes)
        );

        return abi.encodePacked(header, elementHeader, keccak256("commitments"), mandateData);
    }

    /// @notice Compute expected hash when tokenOut is expanded
    function computeExpectedHashWithTokenOut(bytes calldata compactData)
        external
        view
        returns (bytes32)
    {
        // Parse compact data
        uint256 nonce = uint256(bytes32(compactData[0:32]));
        uint256 expires = uint256(bytes32(compactData[32:64]));

        // Parse otherElements as calldata
        uint256 otherElementsLength = uint256(bytes32(compactData[64:96]));
        bytes32[] calldata otherElements;
        assembly {
            otherElements.offset := add(compactData.offset, 96)
            otherElements.length := otherElementsLength
        }
        uint256 offset = 96 + otherElementsLength * 32;

        // Parse element
        address arbiter = address(bytes20(compactData[offset:offset + 20]));
        offset += 32; // arbiter + reserved
        uint256 elementIndex = uint256(bytes32(compactData[offset:offset + 32]));
        offset += 32;
        bytes32 commitmentsHash = bytes32(compactData[offset:offset + 32]);
        offset += 32;

        // Parse TARGET (expanded!)
        address recipient = address(bytes20(compactData[offset:offset + 20]));
        offset += 32; // recipient + reserved
        uint256 targetChainId = uint256(bytes32(compactData[offset:offset + 32]));
        offset += 32;
        uint256 fillExpiry = uint256(bytes32(compactData[offset:offset + 32]));
        offset += 32;

        // Parse tokenOut (expanded!)
        uint256 tokenOutLength = uint256(bytes32(compactData[offset:offset + 32]));
        offset += 32;

        // Create calldata pointer to tokenOut
        uint256[2][] calldata tokenOut;
        assembly {
            tokenOut.offset := add(compactData.offset, offset)
            tokenOut.length := tokenOutLength
        }

        // Hash tokenOut
        bytes32 tokenOutHash = EIP712TypeHashLib.hashTokenOut(tokenOut);
        offset += tokenOutLength * 64;

        // Hash target
        bytes32 targetHash = EIP712TypeHashLib.hashTargetAttributesRaw(
            recipient, tokenOutHash, targetChainId, fillExpiry
        );

        // Parse mandate footer
        uint128 minGas = uint128(bytes16(compactData[offset:offset + 16]));
        offset += 16;
        bytes32 originOpsHash = bytes32(compactData[offset:offset + 32]);
        offset += 32;
        bytes32 destOpsHash = bytes32(compactData[offset:offset + 32]);
        offset += 32;
        bytes32 qualificationHash = bytes32(compactData[offset:offset + 32]);

        // Hash mandate
        bytes32 mandateHash = EIP712TypeHashLib.hashMandateRaw(
            targetHash, minGas, originOpsHash, destOpsHash, qualificationHash
        );

        // Hash element
        bytes32 elementHash =
            EIP712TypeHashLib.hashElementRaw(arbiter, block.chainid, commitmentsHash, mandateHash);

        // Insert at index and hash
        bytes32 allElementsHash = otherElements.insertAtAndHash(elementIndex, elementHash);

        return EIP712TypeHashLib.hashCompact(testAccount, nonce, expires, allElementsHash);
    }

    /// @notice Initialize policy with qualification check
    function _initializePolicyWithQualification(
        address arbiter,
        ParamRules memory paramRules,
        uint256 chainId
    )
        internal
    {
        uint32 modeConfig = _createModeConfig(FIELD_QUALIFICATION, MODE_CHECK_STORAGE);

        // Encode qualification config
        bytes memory qualConfig = abi.encodePacked(
            uint256(1), // count
            chainId,
            arbiter,
            uint8(0), // useArbiterHash = false
            paramRules.rootNodeIndex
        );

        // Encode rules
        qualConfig = abi.encodePacked(qualConfig, uint256(paramRules.rules.length));

        for (uint256 i = 0; i < paramRules.rules.length; i++) {
            qualConfig = abi.encodePacked(
                qualConfig,
                uint8(paramRules.rules[i].condition),
                paramRules.rules[i].offset,
                paramRules.rules[i].length,
                paramRules.rules[i].ref
            );
        }

        // Encode packed nodes
        qualConfig = abi.encodePacked(qualConfig, uint256(paramRules.packedNodes.length));

        for (uint256 i = 0; i < paramRules.packedNodes.length; i++) {
            qualConfig = abi.encodePacked(qualConfig, paramRules.packedNodes[i]);
        }

        bytes memory initData = abi.encodePacked(modeConfig, qualConfig);

        compactClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    /// @notice Create Compact data with qualification
    function _createCompactDataWithQualification(
        address arbiter,
        bytes memory qualificationData,
        uint256 elementIndex
    )
        internal
        view
        returns (bytes memory)
    {
        bytes memory header = _createCompactHeader();
        bytes memory elementHeader = _createElementHeader(arbiter, elementIndex);

        // Create qualification section
        bytes memory qualificationSection = abi.encodePacked(
            uint256(qualificationData.length), // dataLength
            qualificationData // actual qualification data
        );

        bytes memory mandateData = abi.encodePacked(
            keccak256("target"), // targetHash (32 bytes)
            uint256(1), // targetChainId (32 bytes)
            uint128(0), // minGas (16 bytes)
            Constants.NO_OPS, // originOpsHash (32 bytes)
            Constants.NO_OPS, // destOpsHash (32 bytes)
            qualificationSection // qualification with header
        );

        return abi.encodePacked(header, elementHeader, keccak256("commitments"), mandateData);
    }

    /// @notice Compute expected hash when qualification is expanded
    function computeExpectedHashWithQualification(bytes calldata compactData)
        external
        view
        returns (bytes32)
    {
        // Parse compact data
        uint256 nonce = uint256(bytes32(compactData[0:32]));
        uint256 expires = uint256(bytes32(compactData[32:64]));

        // Parse otherElements as calldata
        uint256 otherElementsLength = uint256(bytes32(compactData[64:96]));
        bytes32[] calldata otherElements;
        assembly {
            otherElements.offset := add(compactData.offset, 96)
            otherElements.length := otherElementsLength
        }
        uint256 offset = 96 + otherElementsLength * 32;

        // Parse element
        address arbiter = address(bytes20(compactData[offset:offset + 20]));
        offset += 32; // arbiter + reserved
        uint256 elementIndex = uint256(bytes32(compactData[offset:offset + 32]));
        offset += 32;
        bytes32 commitmentsHash = bytes32(compactData[offset:offset + 32]);
        offset += 32;

        // Parse mandate (non-expanded fields)
        bytes32 targetHash = bytes32(compactData[offset:offset + 32]);
        offset += 32;
        offset += 32; // Skip targetChainId
        uint128 minGas = uint128(bytes16(compactData[offset:offset + 16]));
        offset += 16;
        bytes32 originOpsHash = bytes32(compactData[offset:offset + 32]);
        offset += 32;
        bytes32 destOpsHash = bytes32(compactData[offset:offset + 32]);
        offset += 32;

        // Parse qualification (expanded!)
        uint256 dataLength = uint256(bytes32(compactData[offset:offset + 32]));
        offset += 32;

        // Get qualification data
        bytes calldata qualData = compactData[offset:offset + dataLength];

        bytes32 qualificationHash = keccak256(qualData);

        // Hash mandate
        bytes32 mandateHash = EIP712TypeHashLib.hashMandateRaw(
            targetHash, minGas, originOpsHash, destOpsHash, qualificationHash
        );

        // Hash element
        bytes32 elementHash =
            EIP712TypeHashLib.hashElementRaw(arbiter, block.chainid, commitmentsHash, mandateHash);

        // Insert at index and hash
        bytes32 allElementsHash = otherElements.insertAtAndHash(elementIndex, elementHash);

        return EIP712TypeHashLib.hashCompact(testAccount, nonce, expires, allElementsHash);
    }
}
