// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import {
    Permit2ClaimPolicy_Unit_Test
} from "@test/unit/policies/claim/Permit2ClaimPolicy/Permit2ClaimPolicy.t.sol";

// Contracts
import { Permit2EIP712 } from "@compact-utils/common/Permit2EIP712.sol";

// Libraries
import { EIP712TypeHashLib } from "@compact-utils/types/EIP712TypeHashLib.sol";
import { Bytes32ArrayLib } from "@rhinestone/compact-utils/src/common/Bytes32ArrayLib.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import { ParamCondition } from "@smartsessions/external/policies/ArgPolicy/ArgPolicy.sol";
import {
    MODE_SKIP,
    MODE_CHECK_STORAGE,
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

contract Permit2ClaimPolicy_check1271SignedAction_Test is
    Permit2ClaimPolicy_Unit_Test,
    Permit2EIP712
{
    /*//////////////////////////////////////////////////////////////
                                LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using Bytes32ArrayLib for bytes32[];

    /*//////////////////////////////////////////////////////////////
                                 VARIABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice Test account
    address internal testAccount;

    /// @notice Test config ID
    ConfigId internal testConfigId;

    /// @notice Sample ops hash (non-zero)
    bytes32 internal constant SAMPLE_OPS_HASH =
        0x846ef8d62d3fe7c6389ba4cf29cfcd64b917394bdb51073a3e2b6c5e7051f9e1;

    /// @notice Sample minGas value
    uint128 internal constant SAMPLE_MIN_GAS = 100_000;

    /// @notice Sample qualification hash
    bytes32 internal constant SAMPLE_QUALIFICATION_HASH =
        0x3bd13cad138106aee2896aaa5a6d045fcfdf58343c9673049019baa68885c86a;

    /*//////////////////////////////////////////////////////////////
                               CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() Permit2EIP712(PERMIT2_ADDRESS) { }

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
        (address arbiter,) = makeAddrAndKey("arbiter");

        // Initialize policy with arbiter check
        _initializePolicyWithArbiter(arbiter);

        // Create test data
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 mandateHash = _computeBasicMandateHash();

        // Build calldata
        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            _createBasicMandateData()
        );

        // Compute expected hash
        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        // Check the action
        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "Action with valid arbiter should be allowed");
    }

    /// @notice Test check1271SignedAction with arbiter check - should fail when arbiter doesn't
    /// match
    function test_check1271SignedAction_arbiter_invalid_shouldFail() public {
        (address allowedArbiter,) = makeAddrAndKey("allowedArbiter");
        (address usedArbiter,) = makeAddrAndKey("usedArbiter");

        // Initialize policy with allowed arbiter
        _initializePolicyWithArbiter(allowedArbiter);

        // Create test data with different arbiter
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 mandateHash = _computeBasicMandateHash();

        // Build calldata with wrong arbiter
        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(usedArbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            _createBasicMandateData()
        );

        // Compute expected hash (with used arbiter)
        bytes32 expectedHash =
            _computeExpectedHash(usedArbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        // Check the action
        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertFalse(result, "Action with wrong arbiter should be rejected");
    }

    //-------------------------------------
    // 2) DEADLINE (EXPIRY)
    //-------------------------------------

    /// @notice Test check1271SignedAction with deadline check - should pass when in range
    function test_check1271SignedAction_deadline_valid_shouldPass() public {
        uint128 minDeadline = uint128(block.timestamp + 1800);
        uint128 maxDeadline = uint128(block.timestamp + 7200);
        uint256 actualDeadline = block.timestamp + 3600;

        // Initialize policy with deadline check
        _initializePolicyWithDeadline(minDeadline, maxDeadline);

        // Create test data
        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 mandateHash = _computeBasicMandateHash();

        // Build calldata
        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, actualDeadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            _createBasicMandateData()
        );

        // Compute expected hash
        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, actualDeadline, tokenPermissionsHash, mandateHash);

        // Check the action
        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "Action with valid deadline should be allowed");
    }

    /// @notice Test check1271SignedAction with deadline check - should fail when below min
    function test_check1271SignedAction_deadline_belowMin_shouldFail() public {
        uint128 minDeadline = uint128(block.timestamp + 3600);
        uint128 maxDeadline = uint128(block.timestamp + 7200);
        uint256 actualDeadline = block.timestamp + 1800;

        // Initialize policy with deadline check
        _initializePolicyWithDeadline(minDeadline, maxDeadline);

        // Create test data
        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 mandateHash = _computeBasicMandateHash();

        // Build calldata
        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, actualDeadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            _createBasicMandateData()
        );

        // Compute expected hash
        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, actualDeadline, tokenPermissionsHash, mandateHash);

        // Check the action
        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertFalse(result, "Action with deadline below min should be rejected");
    }

    //-------------------------------------
    // 3) TOKEN IN
    //-------------------------------------

    /// @notice Test check1271SignedAction with tokenIn check - should pass when valid
    function test_check1271SignedAction_tokenIn_valid_shouldPass() public {
        address testToken = makeAddr("testToken");
        uint256 amount = 1000;

        // Initialize policy with tokenIn check (no lockTag for Permit2)
        _initializePolicyWithTokenIn(testToken);

        // Create test data
        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;

        // Compute hashes
        bytes32 tokenPermissionsHash = _computeTokenPermissionsHash(testToken, amount);
        bytes32 mandateHash = _computeBasicMandateHash();

        // Build calldata with tokenPermissions array
        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsArray(testToken, amount),
            _createBasicMandateData()
        );

        // Compute expected hash
        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        // Check the action
        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "Action with valid tokenIn should be allowed");
    }

    /// @notice Test check1271SignedAction with tokenIn check - should fail when token invalid
    function test_check1271SignedAction_tokenIn_invalid_shouldFail() public {
        address allowedToken = makeAddr("allowedToken");
        address usedToken = makeAddr("usedToken");
        uint256 amount = 1000;

        // Initialize policy with allowed token
        _initializePolicyWithTokenIn(allowedToken);

        // Create test data with wrong token
        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;

        // Compute hashes
        bytes32 tokenPermissionsHash = _computeTokenPermissionsHash(usedToken, amount);
        bytes32 mandateHash = _computeBasicMandateHash();

        // Build calldata with wrong token
        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsArray(usedToken, amount),
            _createBasicMandateData()
        );

        // Compute expected hash
        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        // Check the action
        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertFalse(result, "Action with invalid tokenIn should be rejected");
    }

    //-------------------------------------
    // 4) RECIPIENT
    //-------------------------------------

    /// @notice Test check1271SignedAction with recipient check - should pass when valid
    function test_check1271SignedAction_recipient_valid_shouldPass() public {
        address recipient = makeAddr("recipient");
        uint256 targetChainId = 137;

        // Initialize policy with recipient check
        _initializePolicyWithRecipient(recipient, targetChainId);

        // Create test data
        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        uint256 fillExpiry = block.timestamp + 7200;
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 tokenOutHash = keccak256("tokenOut");

        // Compute mandate hash
        bytes32 mandateHash = _computeMandateHash(
            recipient,
            targetChainId,
            fillExpiry,
            tokenOutHash,
            Constants.NO_OPS,
            Constants.NO_OPS,
            SAMPLE_QUALIFICATION_HASH
        );

        // Build calldata with full mandate
        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            _createMandateWithTarget(
                recipient,
                targetChainId,
                fillExpiry,
                tokenOutHash,
                Constants.NO_OPS,
                Constants.NO_OPS,
                SAMPLE_QUALIFICATION_HASH
            )
        );

        // Compute expected hash
        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        // Check the action
        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "Action with valid recipient should be allowed");
    }

    //-------------------------------------
    // 5) ORIGIN OPS
    //-------------------------------------

    /// @notice Test check1271SignedAction with originOps check - should pass when required and
    /// present
    function test_check1271SignedAction_originOps_requiredAndPresent_shouldPass() public {
        // Initialize policy requiring originOps
        _initializePolicyWithOriginOps(true);

        // Create test data
        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        address recipient = makeAddr("recipient");
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 tokenOutHash = keccak256("tokenOut");
        uint256 targetChainId = 137;
        uint256 fillExpiry = block.timestamp + 7200;

        // Compute target hash (since no target validation, we pass targetHash)
        bytes32 targetHash = EIP712TypeHashLib.hashTargetAttributesRaw(
            recipient, tokenOutHash, targetChainId, fillExpiry
        );

        // Compute mandate hash with present originOps
        bytes32 mandateHash = EIP712TypeHashLib.hashMandateRaw(
            targetHash,
            SAMPLE_MIN_GAS,
            SAMPLE_OPS_HASH, // originOps present
            Constants.NO_OPS,
            SAMPLE_QUALIFICATION_HASH
        );

        // Build calldata - NO target expansion since no target checks enabled
        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            targetHash, // pre-computed targetHash (32 bytes)
            targetChainId, // targetChainId (32 bytes)
            SAMPLE_MIN_GAS, // minGas (16 bytes)
            SAMPLE_OPS_HASH, // originOpsHash (32 bytes) - present!
            Constants.NO_OPS, // destOpsHash (32 bytes)
            SAMPLE_QUALIFICATION_HASH // qualificationHash (32 bytes)
        );

        // Compute expected hash
        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        // Check the action
        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "Action with required originOps present should be allowed");
    }

    /// @notice Test check1271SignedAction with originOps check - should fail when required but
    /// missing
    function test_check1271SignedAction_originOps_requiredButMissing_shouldFail() public {
        // Initialize policy requiring originOps
        _initializePolicyWithOriginOps(true);

        // Create test data
        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        uint256 fillExpiry = block.timestamp + 7200;
        address recipient = makeAddr("recipient");
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 tokenOutHash = keccak256("tokenOut");

        // Compute mandate hash with missing originOps
        bytes32 mandateHash = _computeMandateHash(
            recipient,
            block.chainid,
            fillExpiry,
            tokenOutHash,
            Constants.NO_OPS,
            Constants.NO_OPS,
            SAMPLE_QUALIFICATION_HASH
        );

        // Build calldata
        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            _createMandateWithTarget(
                recipient,
                block.chainid,
                fillExpiry,
                tokenOutHash,
                Constants.NO_OPS,
                Constants.NO_OPS,
                SAMPLE_QUALIFICATION_HASH
            )
        );

        // Compute expected hash
        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        // Check the action
        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
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
        uint256 actualFillExpiry = block.timestamp + 5000;
        uint256 targetChainId = 137;

        // Initialize policy with fillExpiry check
        _initializePolicyWithFillExpiry(minExpiry, maxExpiry, targetChainId);

        // Create test data
        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        address recipient = makeAddr("recipient");
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 tokenOutHash = keccak256("tokenOut");

        // Compute mandate hash
        bytes32 mandateHash = _computeMandateHash(
            recipient,
            targetChainId,
            actualFillExpiry,
            tokenOutHash,
            Constants.NO_OPS,
            Constants.NO_OPS,
            SAMPLE_QUALIFICATION_HASH
        );

        // Build calldata
        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            _createMandateWithTarget(
                recipient,
                targetChainId,
                actualFillExpiry,
                tokenOutHash,
                Constants.NO_OPS,
                Constants.NO_OPS,
                SAMPLE_QUALIFICATION_HASH
            )
        );

        // Compute expected hash
        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        // Check the action
        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "Action with valid fillExpiry should be allowed");
    }

    /// @notice Test check1271SignedAction with fillExpiry check - should fail when below min
    function test_check1271SignedAction_fillExpiry_belowMin_shouldFail() public {
        uint128 minExpiry = uint128(block.timestamp + 5000);
        uint128 maxExpiry = uint128(block.timestamp + 10_000);
        uint256 actualFillExpiry = block.timestamp + 1000;
        uint256 targetChainId = 137;

        // Initialize policy with fillExpiry check
        _initializePolicyWithFillExpiry(minExpiry, maxExpiry, targetChainId);

        // Create test data
        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        address recipient = makeAddr("recipient");
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 tokenOutHash = keccak256("tokenOut");

        // Compute mandate hash
        bytes32 mandateHash = _computeMandateHash(
            recipient,
            targetChainId,
            actualFillExpiry,
            tokenOutHash,
            Constants.NO_OPS,
            Constants.NO_OPS,
            SAMPLE_QUALIFICATION_HASH
        );

        // Build calldata
        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            _createMandateWithTarget(
                recipient,
                targetChainId,
                actualFillExpiry,
                tokenOutHash,
                Constants.NO_OPS,
                Constants.NO_OPS,
                SAMPLE_QUALIFICATION_HASH
            )
        );

        // Compute expected hash
        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        // Check the action
        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertFalse(result, "Action with fillExpiry below min should be rejected");
    }

    //-------------------------------------
    // 7) TOKEN OUT
    //-------------------------------------

    /// @notice Test check1271SignedAction with tokenOut check - should pass when valid
    function test_check1271SignedAction_tokenOut_valid_shouldPass() public {
        address testToken = makeAddr("testToken");
        uint256 amount = 500;
        uint256 targetChainId = 137;

        // Initialize policy with tokenOut check
        _initializePolicyWithTokenOut(testToken, targetChainId);

        // Create test data
        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        uint256 fillExpiry = block.timestamp + 7200;
        address recipient = makeAddr("recipient");
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");

        // Compute hashes
        bytes32 tokenOutHash = _computeTokenOutHash(testToken, amount);
        bytes32 mandateHash = _computeMandateHash(
            recipient,
            targetChainId,
            fillExpiry,
            tokenOutHash,
            Constants.NO_OPS,
            Constants.NO_OPS,
            SAMPLE_QUALIFICATION_HASH
        );

        // Build calldata with tokenOut array
        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            _createMandateWithTokenOut(
                recipient,
                targetChainId,
                fillExpiry,
                testToken,
                amount,
                Constants.NO_OPS,
                Constants.NO_OPS,
                SAMPLE_QUALIFICATION_HASH
            )
        );

        // Compute expected hash
        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        // Check the action
        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "Action with valid tokenOut should be allowed");
    }

    /// @notice Test check1271SignedAction with tokenOut check - should fail when token invalid
    function test_check1271SignedAction_tokenOut_invalidToken_shouldFail() public {
        address allowedToken = makeAddr("allowedToken");
        address usedToken = makeAddr("usedToken");
        uint256 amount = 500;
        uint256 targetChainId = 137;

        // Initialize policy with tokenOut check for allowedToken
        _initializePolicyWithTokenOut(allowedToken, targetChainId);

        // Create test data with wrong token
        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        uint256 fillExpiry = block.timestamp + 7200;
        address recipient = makeAddr("recipient");
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");

        // Compute hashes with wrong token
        bytes32 tokenOutHash = _computeTokenOutHash(usedToken, amount);
        bytes32 mandateHash = _computeMandateHash(
            recipient,
            targetChainId,
            fillExpiry,
            tokenOutHash,
            Constants.NO_OPS,
            Constants.NO_OPS,
            SAMPLE_QUALIFICATION_HASH
        );

        // Build calldata with wrong token
        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            _createMandateWithTokenOut(
                recipient,
                targetChainId,
                fillExpiry,
                usedToken,
                amount,
                Constants.NO_OPS,
                Constants.NO_OPS,
                SAMPLE_QUALIFICATION_HASH
            )
        );

        // Compute expected hash
        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        // Check the action
        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
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

        // Initialize policy requiring destOps for targetChainId
        _initializePolicyWithDestOps(true, targetChainId);

        // Create test data
        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        address recipient = makeAddr("recipient");
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 tokenOutHash = keccak256("tokenOut");
        uint256 fillExpiry = block.timestamp + 7200;

        // Compute target hash (since no target validation, we pass targetHash)
        bytes32 targetHash = EIP712TypeHashLib.hashTargetAttributesRaw(
            recipient, tokenOutHash, targetChainId, fillExpiry
        );

        // Compute mandate hash with present destOps
        bytes32 mandateHash = EIP712TypeHashLib.hashMandateRaw(
            targetHash,
            SAMPLE_MIN_GAS,
            Constants.NO_OPS,
            SAMPLE_OPS_HASH, // destOps present
            SAMPLE_QUALIFICATION_HASH
        );

        // Build calldata - NO target expansion since no target checks enabled
        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            targetHash, // pre-computed targetHash (32 bytes)
            targetChainId, // targetChainId (32 bytes)
            SAMPLE_MIN_GAS, // minGas (16 bytes)
            Constants.NO_OPS, // originOpsHash (32 bytes)
            SAMPLE_OPS_HASH, // destOpsHash (32 bytes) - present!
            SAMPLE_QUALIFICATION_HASH // qualificationHash (32 bytes)
        );

        // Compute expected hash
        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        // Check the action
        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "Action with required destOps present should be allowed");
    }

    /// @notice Test check1271SignedAction with destOps check - should fail when required but
    /// missing
    function test_check1271SignedAction_destOps_requiredButMissing_shouldFail() public {
        uint256 targetChainId = 137;

        // Initialize policy requiring destOps
        _initializePolicyWithDestOps(true, targetChainId);

        // Create test data
        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        uint256 fillExpiry = block.timestamp + 7200;
        address recipient = makeAddr("recipient");
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 tokenOutHash = keccak256("tokenOut");

        // Compute mandate hash with missing destOps
        bytes32 mandateHash = _computeMandateHash(
            recipient,
            targetChainId,
            fillExpiry,
            tokenOutHash,
            Constants.NO_OPS,
            Constants.NO_OPS,
            SAMPLE_QUALIFICATION_HASH
        );

        // Build calldata
        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            _createMandateWithTarget(
                recipient,
                targetChainId,
                fillExpiry,
                tokenOutHash,
                Constants.NO_OPS,
                Constants.NO_OPS,
                SAMPLE_QUALIFICATION_HASH
            )
        );

        // Compute expected hash
        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        // Check the action
        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertFalse(result, "Action with required destOps missing should be rejected");
    }

    //-------------------------------------
    // 9) QUALIFICATION
    //-------------------------------------

    /// @notice Test check1271SignedAction with qualification check - should pass when valid
    function test_check1271SignedAction_qualification_valid_shouldPass() public {
        uint64 offset = 0;
        bytes32 expectedValue = bytes32(uint256(0x123));

        // Initialize policy - NOTE: qualification is keyed by chainId + arbiter
        // The chainId used for lookup is block.chainid (origin chain), not targetChainId
        (address arbiter,) = makeAddrAndKey("arbiter");
        _initializePolicyWithQualification(arbiter, block.chainid, offset, expectedValue);

        // Create test data
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        address recipient = makeAddr("recipient");
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 tokenOutHash = keccak256("tokenOut");
        uint256 targetChainId = 137;
        uint256 fillExpiry = block.timestamp + 7200;

        // Build qualification data with expected value
        bytes memory qualificationData = abi.encodePacked(expectedValue);
        bytes32 qualificationHash = keccak256(qualificationData);

        // Compute target hash
        bytes32 targetHash = EIP712TypeHashLib.hashTargetAttributesRaw(
            recipient, tokenOutHash, targetChainId, fillExpiry
        );

        // Compute mandate hash
        bytes32 mandateHash = EIP712TypeHashLib.hashMandateRaw(
            targetHash, SAMPLE_MIN_GAS, Constants.NO_OPS, Constants.NO_OPS, qualificationHash
        );

        // Build calldata with qualification data expanded
        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            targetHash, // pre-computed targetHash (32 bytes)
            targetChainId, // targetChainId (32 bytes)
            SAMPLE_MIN_GAS, // minGas (16 bytes)
            Constants.NO_OPS, // originOpsHash (32 bytes)
            Constants.NO_OPS, // destOpsHash (32 bytes)
            uint256(qualificationData.length), // qualification data length
            qualificationData // qualification data
        );

        // Compute expected hash
        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        // Check the action
        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "Action with valid qualification should be allowed");
    }

    /// @notice Test check1271SignedAction with qualification check - should fail when invalid
    function test_check1271SignedAction_qualification_invalid_shouldFail() public {
        uint64 offset = 0;
        bytes32 expectedValue = bytes32(uint256(0x123));
        bytes32 wrongValue = bytes32(uint256(0x456));

        // Initialize policy - chainId must be block.chainid for lookup to find config
        (address arbiter,) = makeAddrAndKey("arbiter");
        _initializePolicyWithQualification(arbiter, block.chainid, offset, expectedValue);

        // Create test data
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        address recipient = makeAddr("recipient");
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 tokenOutHash = keccak256("tokenOut");
        uint256 targetChainId = 137;
        uint256 fillExpiry = block.timestamp + 7200;

        // Build qualification data with WRONG value
        bytes memory qualificationData = abi.encodePacked(wrongValue);
        bytes32 qualificationHash = keccak256(qualificationData);

        // Compute target hash
        bytes32 targetHash = EIP712TypeHashLib.hashTargetAttributesRaw(
            recipient, tokenOutHash, targetChainId, fillExpiry
        );

        // Compute mandate hash
        bytes32 mandateHash = EIP712TypeHashLib.hashMandateRaw(
            targetHash, SAMPLE_MIN_GAS, Constants.NO_OPS, Constants.NO_OPS, qualificationHash
        );

        // Build calldata with qualification data expanded
        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            targetHash, // pre-computed targetHash (32 bytes)
            targetChainId, // targetChainId (32 bytes)
            SAMPLE_MIN_GAS, // minGas (16 bytes)
            Constants.NO_OPS, // originOpsHash (32 bytes)
            Constants.NO_OPS, // destOpsHash (32 bytes)
            uint256(qualificationData.length), // qualification data length
            qualificationData // qualification data
        );

        // Compute expected hash
        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        // Check the action
        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
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

        permit2ClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    /// @notice Initialize policy with deadline check
    function _initializePolicyWithDeadline(uint128 min, uint128 max) internal {
        uint32 modeConfig = _createModeConfig(FIELD_EXPIRY, MODE_CHECK_STORAGE);
        bytes memory initData = abi.encodePacked(modeConfig, uint256(min) | (uint256(max) << 128));

        permit2ClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    /// @notice Initialize policy with tokenIn check (Permit2 format - no lockTag)
    function _initializePolicyWithTokenIn(address token) internal {
        uint32 modeConfig = _createModeConfig(FIELD_TOKEN_IN, MODE_CHECK_STORAGE);

        bytes memory initData =
            abi.encodePacked(modeConfig, uint256(1), uint256(block.chainid), token);

        permit2ClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    /// @notice Initialize policy with recipient check
    function _initializePolicyWithRecipient(
        address recipient,
        uint256 targetChainId
    )
        internal
    {
        uint32 modeConfig = _createModeConfig(FIELD_RECIPIENT, MODE_CHECK_STORAGE);
        bytes memory initData = abi.encodePacked(modeConfig, uint256(1), targetChainId, recipient);

        permit2ClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    /// @notice Initialize policy with originOps check
    function _initializePolicyWithOriginOps(bool required) internal {
        uint32 modeConfig = _createModeConfig(FIELD_ORIGIN_OPS, MODE_CHECK_STORAGE);
        bytes memory initData =
            abi.encodePacked(modeConfig, uint256(1), block.chainid, uint8(required ? 1 : 0));

        permit2ClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
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
            modeConfig, uint256(1), targetChainId, uint256(min) | (uint256(max) << 128)
        );

        permit2ClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    /// @notice Initialize policy with tokenOut check
    function _initializePolicyWithTokenOut(address token, uint256 targetChainId) internal {
        uint32 modeConfig = _createModeConfig(FIELD_TOKEN_OUT, MODE_CHECK_STORAGE);
        bytes memory initData = abi.encodePacked(modeConfig, uint256(1), targetChainId, token);

        permit2ClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    /// @notice Initialize policy with destOps check
    function _initializePolicyWithDestOps(bool required, uint256 targetChainId) internal {
        uint32 modeConfig = _createModeConfig(FIELD_DEST_OPS, MODE_CHECK_STORAGE);
        bytes memory initData =
            abi.encodePacked(modeConfig, uint256(1), targetChainId, uint8(required ? 1 : 0));

        permit2ClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    /// @notice Initialize policy with qualification check
    /// @notice Initialize policy with qualification check
    function _initializePolicyWithQualification(
        address arbiter,
        uint256 targetChainId,
        uint64 offset,
        bytes32 refValue
    )
        internal
    {
        uint32 modeConfig = _createModeConfig(FIELD_QUALIFICATION, MODE_CHECK_STORAGE);

        bytes memory initData = abi.encodePacked(
            modeConfig,
            uint256(1), // count
            targetChainId, // chainId for lookup
            arbiter, // arbiter for lookup (the Permit2 spender)
            uint8(0), // useArbiterHash = false
            uint8(0), // rootNodeIndex
            uint256(1), // ruleCount
            uint8(ParamCondition.EQUAL),
            uint64(offset),
            uint8(32),
            refValue,
            uint256(1), // packedNodesCount
            uint256(0) // node: type=RULE, ruleIndex=0
        );

        permit2ClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    /// @notice Creates Permit2 header
    function _createPermit2Header(
        address arbiter,
        uint256 nonce,
        uint256 deadline
    )
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(arbiter, nonce, deadline);
    }

    /// @notice Creates tokenPermissions hash (when MODE_SKIP)
    function _createTokenPermissionsHash(bytes32 hash) internal pure returns (bytes memory) {
        return abi.encodePacked(hash);
    }

    /// @notice Creates tokenPermissions array
    function _createTokenPermissionsArray(
        address token,
        uint256 amount
    )
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(uint256(1), uint256(uint160(token)), amount);
    }

    /// @notice Creates basic mandate data with default values
    function _createBasicMandateData() internal pure returns (bytes memory) {
        bytes32 targetHash = keccak256("target");
        bytes32 qualificationHash = keccak256("qualification");
        return abi.encodePacked(
            targetHash,
            uint256(1),
            SAMPLE_MIN_GAS,
            Constants.NO_OPS,
            Constants.NO_OPS,
            qualificationHash
        );
    }

    /// @notice Computes the mandate hash for basic mandate data
    function _computeBasicMandateHash() internal pure returns (bytes32) {
        bytes32 targetHash = keccak256("target");
        bytes32 qualificationHash = keccak256("qualification");
        return EIP712TypeHashLib.hashMandateRaw(
            targetHash, SAMPLE_MIN_GAS, Constants.NO_OPS, Constants.NO_OPS, qualificationHash
        );
    }

    /// @notice Creates mandate data when all target fields SKIP
    function _createMandateData(
        bytes32 targetHash,
        uint256 targetChainId,
        bytes32 originOpsHash,
        bytes32 destOpsHash,
        bytes32 qualificationHash
    )
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            targetHash, targetChainId, SAMPLE_MIN_GAS, originOpsHash, destOpsHash, qualificationHash
        );
    }

    /// @notice Creates full mandate struct when target fields need validation
    function _createMandateWithTarget(
        address recipient,
        uint256 targetChainId,
        uint256 fillExpiry,
        bytes32 tokenOutHash,
        bytes32 originOpsHash,
        bytes32 destOpsHash,
        bytes32 qualificationHash
    )
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            recipient, // 20 bytes
            targetChainId,
            fillExpiry,
            tokenOutHash,
            SAMPLE_MIN_GAS,
            originOpsHash,
            destOpsHash,
            qualificationHash
        );
    }

    /// @notice Creates mandate with tokenOut array instead of hash
    function _createMandateWithTokenOut(
        address recipient,
        uint256 targetChainId,
        uint256 fillExpiry,
        address tokenOut,
        uint256 tokenOutAmount,
        bytes32 originOpsHash,
        bytes32 destOpsHash,
        bytes32 qualificationHash
    )
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            recipient, // 20 bytes
            targetChainId,
            fillExpiry,
            uint256(1), // tokenOut length
            uint256(uint160(tokenOut)),
            tokenOutAmount,
            SAMPLE_MIN_GAS,
            originOpsHash,
            destOpsHash,
            qualificationHash
        );
    }

    /// @notice Creates mandate with qualification data instead of hash
    function _createMandateWithQualification(
        address recipient,
        uint256 targetChainId,
        uint256 fillExpiry,
        bytes32 tokenOutHash,
        bytes32 originOpsHash,
        bytes32 destOpsHash,
        bytes memory qualificationData
    )
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            recipient, // 20 bytes
            targetChainId,
            fillExpiry,
            tokenOutHash,
            SAMPLE_MIN_GAS,
            originOpsHash,
            destOpsHash,
            uint256(qualificationData.length),
            qualificationData
        );
    }

    /// @notice Computes expected Permit2 hash for validation
    function _computeExpectedHash(
        address arbiter,
        uint256 nonce,
        uint256 deadline,
        bytes32 tokenPermissionsHash,
        bytes32 mandateHash
    )
        internal
        view
        returns (bytes32)
    {
        bytes32 structHash = EIP712TypeHashLib.hashPermit2(
            tokenPermissionsHash, arbiter, nonce, deadline, mandateHash
        );

        return _permit2HashTypedData(structHash);
    }

    /// @notice Computes tokenPermissions hash from array (external for calldata)
    function computeTokenPermissionsHash(uint256[2][] calldata tokenPermissions)
        external
        pure
        returns (bytes32)
    {
        return EIP712TypeHashLib.hashTokenPermissions(tokenPermissions);
    }

    /// @notice Helper to build tokenPermissions array and compute hash
    function _computeTokenPermissionsHash(
        address token,
        uint256 amount
    )
        internal
        view
        returns (bytes32)
    {
        uint256[2][] memory tokenPermissions = new uint256[2][](1);
        tokenPermissions[0][0] = uint256(uint160(token));
        tokenPermissions[0][1] = amount;

        return this.computeTokenPermissionsHash(tokenPermissions);
    }

    /// @notice Computes tokenOut hash from array (external for calldata)
    function computeTokenOutHash(uint256[2][] calldata tokenOut) external pure returns (bytes32) {
        return EIP712TypeHashLib.hashTokenOut(tokenOut);
    }

    /// @notice Helper to build tokenOut array and compute hash
    function _computeTokenOutHash(
        address token,
        uint256 amount
    )
        internal
        view
        returns (bytes32)
    {
        uint256[2][] memory tokenOut = new uint256[2][](1);
        tokenOut[0][0] = uint256(uint160(token));
        tokenOut[0][1] = amount;

        return this.computeTokenOutHash(tokenOut);
    }

    /// @notice Computes mandate hash from components
    function _computeMandateHash(
        address recipient,
        uint256 targetChainId,
        uint256 fillExpiry,
        bytes32 tokenOutHash,
        bytes32 originOpsHash,
        bytes32 destOpsHash,
        bytes32 qualificationHash
    )
        internal
        pure
        returns (bytes32)
    {
        bytes32 targetHash = EIP712TypeHashLib.hashTargetAttributesRaw(
            recipient, tokenOutHash, targetChainId, fillExpiry
        );

        return EIP712TypeHashLib.hashMandateRaw(
            targetHash, SAMPLE_MIN_GAS, originOpsHash, destOpsHash, qualificationHash
        );
    }
}
