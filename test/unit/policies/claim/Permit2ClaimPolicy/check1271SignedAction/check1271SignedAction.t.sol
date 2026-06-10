// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import {
    Permit2ClaimPolicy_Unit_Test
} from "@test/unit/policies/claim/Permit2ClaimPolicy/Permit2ClaimPolicy.t.sol";

// Contracts
import { Permit2EIP712 } from "@compact-utils/common/Permit2EIP712.sol";

// Mocks
import { MockSubPolicy } from "@mocks/MockSubPolicy.sol";

// Libraries
import { EIP712TypeHashLib } from "@compact-utils/types/EIP712TypeHashLib.sol";
import { Bytes32ArrayLib } from "@rhinestone/compact-utils/src/common/Bytes32ArrayLib.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import { ParamCondition } from "@smartsessions/external/policies/ArgPolicy/ArgPolicy.sol";
import {
    MODE_SKIP,
    MODE_CHECK_STORAGE,
    MODE_CHECK_CATCHALL,
    MODE_CHECK_SUBPOLICY,
    FIELD_ARBITER,
    FIELD_EXPIRY,
    FIELD_TOKEN_IN,
    FIELD_RECIPIENT,
    FIELD_FILL_EXPIRY,
    FIELD_TOKEN_OUT,
    FIELD_ORIGIN_OPS,
    FIELD_DEST_OPS,
    FIELD_QUALIFICATION,
    FIELD_RECIPIENT_IS_SPONSOR,
    ANY_ADDRESS
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

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

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
    // 0) UNINITIALIZED / HASH
    //-------------------------------------

    /// @notice Test uninitialized policy returns true (all SKIP)
    function test_check1271SignedAction_uninitialized_shouldReturnTrue() public {
        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 mandateHash = _computeBasicMandateHash();

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            mandateHash
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "Uninitialized policy should return true");
    }

    /// @notice Test hash matches - should return true
    function test_check1271SignedAction_hash_matches_shouldReturnTrue() public {
        (address arbiter,) = makeAddrAndKey("arbiter");
        _initializePolicyWithArbiter(arbiter, MODE_CHECK_STORAGE);

        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 mandateHash = _computeBasicMandateHash();

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            mandateHash
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "Matching hash should return true");
    }

    /// @notice Test hash mismatch - should return false
    function test_check1271SignedAction_hash_mismatch_shouldReturnFalse() public {
        (address arbiter,) = makeAddrAndKey("arbiter");
        _initializePolicyWithArbiter(arbiter, MODE_CHECK_STORAGE);

        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 mandateHash = _computeBasicMandateHash();

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            mandateHash
        );

        bytes32 wrongHash = keccak256("wrongHash");

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, wrongHash, permit2Data
        );

        assertFalse(result, "Mismatched hash should return false");
    }

    //-------------------------------------
    // 1) ARBITER
    //-------------------------------------

    // --- SKIP ---

    /// @notice Test arbiter SKIP mode - should return true for any arbiter
    function test_check1271SignedAction_arbiter_skip_shouldReturnTrue() public {
        // No initialization - defaults to SKIP
        (address arbiter,) = makeAddrAndKey("anyArbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 mandateHash = _computeBasicMandateHash();

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            mandateHash
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "SKIP mode should return true for any arbiter");
    }

    // --- STORAGE ---

    /// @notice Test arbiter storage mode - should pass when arbiter matches
    function test_check1271SignedAction_arbiter_storage_valid_shouldPass() public {
        (address arbiter,) = makeAddrAndKey("arbiter");
        _initializePolicyWithArbiter(arbiter, MODE_CHECK_STORAGE);

        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 mandateHash = _computeBasicMandateHash();

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            mandateHash
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "Action with valid arbiter should be allowed");
    }

    /// @notice Test arbiter storage mode - should fail when arbiter doesn't match
    function test_check1271SignedAction_arbiter_storage_invalid_shouldFail() public {
        (address allowedArbiter,) = makeAddrAndKey("allowedArbiter");
        (address usedArbiter,) = makeAddrAndKey("usedArbiter");
        _initializePolicyWithArbiter(allowedArbiter, MODE_CHECK_STORAGE);

        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 mandateHash = _computeBasicMandateHash();

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(usedArbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            mandateHash
        );

        bytes32 expectedHash =
            _computeExpectedHash(usedArbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertFalse(result, "Action with wrong arbiter should be rejected");
    }

    /// @notice Test arbiter storage mode - should pass when multiple arbiters whitelisted
    function test_check1271SignedAction_arbiter_storage_multipleWhitelisted_shouldPass() public {
        (address arbiter1,) = makeAddrAndKey("arbiter1");
        (address arbiter2,) = makeAddrAndKey("arbiter2");
        _initializePolicyWithMultipleArbiters(arbiter1, arbiter2, MODE_CHECK_STORAGE);

        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 mandateHash = _computeBasicMandateHash();

        // Use second arbiter
        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter2, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            mandateHash
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter2, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "Second whitelisted arbiter should be allowed");
    }

    // --- CATCHALL ---

    /// @notice Test arbiter catchall mode - should pass when arbiter in catchall whitelist
    function test_check1271SignedAction_arbiter_catchall_valid_shouldPass() public {
        (address arbiter,) = makeAddrAndKey("arbiter");
        _initializePolicyWithArbiter(arbiter, MODE_CHECK_CATCHALL);

        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 mandateHash = _computeBasicMandateHash();

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            mandateHash
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "Catchall valid arbiter should be allowed");
    }

    /// @notice Test arbiter catchall mode - should fail when arbiter not in catchall whitelist
    function test_check1271SignedAction_arbiter_catchall_invalid_shouldFail() public {
        (address allowedArbiter,) = makeAddrAndKey("allowedArbiter");
        (address usedArbiter,) = makeAddrAndKey("usedArbiter");
        _initializePolicyWithArbiter(allowedArbiter, MODE_CHECK_CATCHALL);

        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 mandateHash = _computeBasicMandateHash();

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(usedArbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            mandateHash
        );

        bytes32 expectedHash =
            _computeExpectedHash(usedArbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertFalse(result, "Catchall invalid arbiter should be rejected");
    }

    // --- SUBPOLICY ---

    /// @notice Test arbiter subpolicy mode - should pass when subpolicy approves
    function test_check1271SignedAction_arbiter_subpolicy_approves_shouldPass() public {
        (address arbiter,) = makeAddrAndKey("arbiter");
        mockSubPolicy.setReturnValue(true);
        _initializePolicyWithArbiterSubpolicy(address(mockSubPolicy));

        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 mandateHash = _computeBasicMandateHash();

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            mandateHash
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "Subpolicy approval should be allowed");
    }

    /// @notice Test arbiter subpolicy mode - should fail when subpolicy rejects
    function test_check1271SignedAction_arbiter_subpolicy_rejects_shouldFail() public {
        (address arbiter,) = makeAddrAndKey("arbiter");
        mockSubPolicy.setReturnValue(false);
        _initializePolicyWithArbiterSubpolicy(address(mockSubPolicy));

        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 mandateHash = _computeBasicMandateHash();

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            mandateHash
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertFalse(result, "Subpolicy rejection should be rejected");
    }

    //-------------------------------------
    // 2) EXPIRY (DEADLINE)
    //-------------------------------------

    // --- SKIP ---

    /// @notice Test expiry SKIP mode - should return true for any deadline
    function test_check1271SignedAction_expiry_skip_shouldReturnTrue() public {
        // No initialization - defaults to SKIP
        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 mandateHash = _computeBasicMandateHash();

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            mandateHash
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "SKIP mode should return true for any deadline");
    }

    // --- STORAGE ---

    /// @notice Test expiry storage mode - should pass when deadline within bounds
    function test_check1271SignedAction_expiry_storage_withinBounds_shouldPass() public {
        uint128 minDeadline = uint128(block.timestamp + 1800);
        uint128 maxDeadline = uint128(block.timestamp + 7200);
        uint256 actualDeadline = block.timestamp + 3600;
        _initializePolicyWithExpiry(minDeadline, maxDeadline);

        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 mandateHash = _computeBasicMandateHash();

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, actualDeadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            mandateHash
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, actualDeadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "Action with valid deadline should be allowed");
    }

    /// @notice Test expiry storage mode - should pass when deadline equals min
    function test_check1271SignedAction_expiry_storage_equalsMin_shouldPass() public {
        uint128 minDeadline = uint128(block.timestamp + 1800);
        uint128 maxDeadline = uint128(block.timestamp + 7200);
        _initializePolicyWithExpiry(minDeadline, maxDeadline);

        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 mandateHash = _computeBasicMandateHash();

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, uint256(minDeadline)),
            _createTokenPermissionsHash(tokenPermissionsHash),
            mandateHash
        );

        bytes32 expectedHash = _computeExpectedHash(
            arbiter, nonce, uint256(minDeadline), tokenPermissionsHash, mandateHash
        );

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "Deadline equals min should be allowed");
    }

    /// @notice Test expiry storage mode - should pass when deadline equals max
    function test_check1271SignedAction_expiry_storage_equalsMax_shouldPass() public {
        uint128 minDeadline = uint128(block.timestamp + 1800);
        uint128 maxDeadline = uint128(block.timestamp + 7200);
        _initializePolicyWithExpiry(minDeadline, maxDeadline);

        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 mandateHash = _computeBasicMandateHash();

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, uint256(maxDeadline)),
            _createTokenPermissionsHash(tokenPermissionsHash),
            mandateHash
        );

        bytes32 expectedHash = _computeExpectedHash(
            arbiter, nonce, uint256(maxDeadline), tokenPermissionsHash, mandateHash
        );

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "Deadline equals max should be allowed");
    }

    /// @notice Test expiry storage mode - should fail when deadline below min
    function test_check1271SignedAction_expiry_storage_belowMin_shouldFail() public {
        uint128 minDeadline = uint128(block.timestamp + 3600);
        uint128 maxDeadline = uint128(block.timestamp + 7200);
        uint256 actualDeadline = block.timestamp + 1800;
        _initializePolicyWithExpiry(minDeadline, maxDeadline);

        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 mandateHash = _computeBasicMandateHash();

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, actualDeadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            mandateHash
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, actualDeadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertFalse(result, "Action with deadline below min should be rejected");
    }

    /// @notice Test expiry storage mode - should fail when deadline above max
    function test_check1271SignedAction_expiry_storage_aboveMax_shouldFail() public {
        uint128 minDeadline = uint128(block.timestamp + 1800);
        uint128 maxDeadline = uint128(block.timestamp + 3600);
        uint256 actualDeadline = block.timestamp + 7200;
        _initializePolicyWithExpiry(minDeadline, maxDeadline);

        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 mandateHash = _computeBasicMandateHash();

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, actualDeadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            mandateHash
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, actualDeadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertFalse(result, "Action with deadline above max should be rejected");
    }

    // --- SUBPOLICY ---

    /// @notice Test expiry subpolicy mode - should pass when subpolicy approves
    function test_check1271SignedAction_expiry_subpolicy_approves_shouldPass() public {
        mockSubPolicy.setReturnValue(true);
        _initializePolicyWithExpirySubpolicy(address(mockSubPolicy));

        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 mandateHash = _computeBasicMandateHash();

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            mandateHash
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "Subpolicy approval should be allowed");
    }

    /// @notice Test expiry subpolicy mode - should fail when subpolicy rejects
    function test_check1271SignedAction_expiry_subpolicy_rejects_shouldFail() public {
        mockSubPolicy.setReturnValue(false);
        _initializePolicyWithExpirySubpolicy(address(mockSubPolicy));

        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 mandateHash = _computeBasicMandateHash();

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            mandateHash
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertFalse(result, "Subpolicy rejection should be rejected");
    }

    //-------------------------------------
    // 3) TOKEN IN
    //-------------------------------------

    // --- SKIP ---

    /// @notice Test tokenIn SKIP mode - should return true for any tokenIn
    function test_check1271SignedAction_tokenIn_skip_shouldReturnTrue() public {
        // No initialization - defaults to SKIP
        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 mandateHash = _computeBasicMandateHash();

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            mandateHash
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "SKIP mode should return true for any tokenIn");
    }

    // --- STORAGE ---

    /// @notice Test tokenIn storage mode - should pass when token whitelisted
    function test_check1271SignedAction_tokenIn_storage_valid_shouldPass() public {
        address testToken = makeAddr("testToken");
        uint256 amount = 1000;
        _initializePolicyWithTokenIn(testToken, MODE_CHECK_STORAGE);

        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;

        bytes32 tokenPermissionsHash = _computeTokenPermissionsHash(testToken, amount);
        bytes32 mandateHash = _computeBasicMandateHash();

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsArray(testToken, amount),
            mandateHash
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "Action with valid tokenIn should be allowed");
    }

    /// @notice Test tokenIn storage mode - should fail when token not whitelisted
    function test_check1271SignedAction_tokenIn_storage_tokenNotWhitelisted_shouldFail() public {
        address allowedToken = makeAddr("allowedToken");
        address usedToken = makeAddr("usedToken");
        uint256 amount = 1000;
        _initializePolicyWithTokenIn(allowedToken, MODE_CHECK_STORAGE);

        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;

        bytes32 tokenPermissionsHash = _computeTokenPermissionsHash(usedToken, amount);
        bytes32 mandateHash = _computeBasicMandateHash();

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsArray(usedToken, amount),
            mandateHash
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertFalse(result, "Action with invalid tokenIn should be rejected");
    }

    /// @notice Test tokenIn storage mode - should pass when multiple tokens whitelisted
    function test_check1271SignedAction_tokenIn_storage_multipleWhitelisted_shouldPass() public {
        address token1 = makeAddr("token1");
        address token2 = makeAddr("token2");
        uint256 amount = 1000;
        _initializePolicyWithMultipleTokensIn(token1, token2, MODE_CHECK_STORAGE);

        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;

        // Use second token
        bytes32 tokenPermissionsHash = _computeTokenPermissionsHash(token2, amount);
        bytes32 mandateHash = _computeBasicMandateHash();

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsArray(token2, amount),
            mandateHash
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "Second whitelisted token should be allowed");
    }

    // --- CATCHALL ---

    /// @notice Test tokenIn catchall mode - should pass when token in catchall whitelist
    function test_check1271SignedAction_tokenIn_catchall_valid_shouldPass() public {
        address testToken = makeAddr("testToken");
        uint256 amount = 1000;
        _initializePolicyWithTokenIn(testToken, MODE_CHECK_CATCHALL);

        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;

        bytes32 tokenPermissionsHash = _computeTokenPermissionsHash(testToken, amount);
        bytes32 mandateHash = _computeBasicMandateHash();

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsArray(testToken, amount),
            mandateHash
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "Catchall valid tokenIn should be allowed");
    }

    /// @notice Test tokenIn catchall mode - should fail when token not in catchall whitelist
    function test_check1271SignedAction_tokenIn_catchall_invalid_shouldFail() public {
        address allowedToken = makeAddr("allowedToken");
        address usedToken = makeAddr("usedToken");
        uint256 amount = 1000;
        _initializePolicyWithTokenIn(allowedToken, MODE_CHECK_CATCHALL);

        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;

        bytes32 tokenPermissionsHash = _computeTokenPermissionsHash(usedToken, amount);
        bytes32 mandateHash = _computeBasicMandateHash();

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsArray(usedToken, amount),
            mandateHash
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertFalse(result, "Catchall invalid tokenIn should be rejected");
    }

    // --- SUBPOLICY ---

    /// @notice Test tokenIn subpolicy mode - should pass when subpolicy approves
    function test_check1271SignedAction_tokenIn_subpolicy_approves_shouldPass() public {
        address testToken = makeAddr("testToken");
        uint256 amount = 1000;
        mockSubPolicy.setReturnValue(true);
        _initializePolicyWithTokenInSubpolicy(address(mockSubPolicy));

        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;

        bytes32 tokenPermissionsHash = _computeTokenPermissionsHash(testToken, amount);
        bytes32 mandateHash = _computeBasicMandateHash();

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsArray(testToken, amount),
            mandateHash
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "Subpolicy approval should be allowed");
    }

    /// @notice Test tokenIn subpolicy mode - should fail when subpolicy rejects
    function test_check1271SignedAction_tokenIn_subpolicy_rejects_shouldFail() public {
        address testToken = makeAddr("testToken");
        uint256 amount = 1000;
        mockSubPolicy.setReturnValue(false);
        _initializePolicyWithTokenInSubpolicy(address(mockSubPolicy));

        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;

        bytes32 tokenPermissionsHash = _computeTokenPermissionsHash(testToken, amount);
        bytes32 mandateHash = _computeBasicMandateHash();

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsArray(testToken, amount),
            mandateHash
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertFalse(result, "Subpolicy rejection should be rejected");
    }

    //-------------------------------------
    // 4) RECIPIENT
    //-------------------------------------

    // --- SKIP ---

    /// @notice Test recipient SKIP mode - should return true for any recipient
    function test_check1271SignedAction_recipient_skip_shouldReturnTrue() public {
        // No initialization - defaults to SKIP
        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 mandateHash = _computeBasicMandateHash();

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            mandateHash
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "SKIP mode should return true for any recipient");
    }

    // --- STORAGE ---

    /// @notice Test recipient storage mode - should pass when recipient matches stored config
    function test_check1271SignedAction_recipient_storage_valid_shouldPass() public {
        address recipient = makeAddr("recipient");
        uint256 targetChainId = 137;
        _initializePolicyWithRecipient(recipient, targetChainId, MODE_CHECK_STORAGE);

        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        uint256 fillExpiry = block.timestamp + 7200;
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 tokenOutHash = keccak256("tokenOut");

        bytes32 mandateHash = _computeMandateHash(
            recipient,
            targetChainId,
            fillExpiry,
            tokenOutHash,
            Constants.NO_OPS,
            Constants.NO_OPS,
            SAMPLE_QUALIFICATION_HASH
        );

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

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "Action with valid recipient should be allowed");
    }

    /// @notice Test recipient storage mode - should fail when recipient does not match
    function test_check1271SignedAction_recipient_storage_invalid_shouldFail() public {
        address allowedRecipient = makeAddr("allowedRecipient");
        address usedRecipient = makeAddr("usedRecipient");
        uint256 targetChainId = 137;
        _initializePolicyWithRecipient(allowedRecipient, targetChainId, MODE_CHECK_STORAGE);

        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        uint256 fillExpiry = block.timestamp + 7200;
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 tokenOutHash = keccak256("tokenOut");

        bytes32 mandateHash = _computeMandateHash(
            usedRecipient,
            targetChainId,
            fillExpiry,
            tokenOutHash,
            Constants.NO_OPS,
            Constants.NO_OPS,
            SAMPLE_QUALIFICATION_HASH
        );

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            _createMandateWithTarget(
                usedRecipient,
                targetChainId,
                fillExpiry,
                tokenOutHash,
                Constants.NO_OPS,
                Constants.NO_OPS,
                SAMPLE_QUALIFICATION_HASH
            )
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertFalse(result, "Action with wrong recipient should be rejected");
    }

    /// @notice Test recipient storage mode - should pass when stored recipient is ANY_ADDRESS
    function test_check1271SignedAction_recipient_storage_anyAddress_shouldPass() public {
        uint256 targetChainId = 137;
        _initializePolicyWithRecipient(ANY_ADDRESS, targetChainId, MODE_CHECK_STORAGE);

        address anyRecipient = makeAddr("anyRecipient");
        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        uint256 fillExpiry = block.timestamp + 7200;
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 tokenOutHash = keccak256("tokenOut");

        bytes32 mandateHash = _computeMandateHash(
            anyRecipient,
            targetChainId,
            fillExpiry,
            tokenOutHash,
            Constants.NO_OPS,
            Constants.NO_OPS,
            SAMPLE_QUALIFICATION_HASH
        );

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            _createMandateWithTarget(
                anyRecipient,
                targetChainId,
                fillExpiry,
                tokenOutHash,
                Constants.NO_OPS,
                Constants.NO_OPS,
                SAMPLE_QUALIFICATION_HASH
            )
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "ANY_ADDRESS should allow any recipient");
    }

    // --- CATCHALL ---

    /// @notice Test recipient catchall mode - should pass when recipient matches catchall config
    function test_check1271SignedAction_recipient_catchall_valid_shouldPass() public {
        address recipient = makeAddr("recipient");
        uint256 targetChainId = 137;
        _initializePolicyWithRecipient(recipient, targetChainId, MODE_CHECK_CATCHALL);

        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        uint256 fillExpiry = block.timestamp + 7200;
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 tokenOutHash = keccak256("tokenOut");

        bytes32 mandateHash = _computeMandateHash(
            recipient,
            targetChainId,
            fillExpiry,
            tokenOutHash,
            Constants.NO_OPS,
            Constants.NO_OPS,
            SAMPLE_QUALIFICATION_HASH
        );

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

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "Catchall valid recipient should be allowed");
    }

    /// @notice Test recipient catchall mode - should fail when recipient not in catchall config
    function test_check1271SignedAction_recipient_catchall_invalid_shouldFail() public {
        address allowedRecipient = makeAddr("allowedRecipient");
        address usedRecipient = makeAddr("usedRecipient");
        uint256 targetChainId = 137;
        _initializePolicyWithRecipient(allowedRecipient, targetChainId, MODE_CHECK_CATCHALL);

        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        uint256 fillExpiry = block.timestamp + 7200;
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 tokenOutHash = keccak256("tokenOut");

        bytes32 mandateHash = _computeMandateHash(
            usedRecipient,
            targetChainId,
            fillExpiry,
            tokenOutHash,
            Constants.NO_OPS,
            Constants.NO_OPS,
            SAMPLE_QUALIFICATION_HASH
        );

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            _createMandateWithTarget(
                usedRecipient,
                targetChainId,
                fillExpiry,
                tokenOutHash,
                Constants.NO_OPS,
                Constants.NO_OPS,
                SAMPLE_QUALIFICATION_HASH
            )
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertFalse(result, "Catchall invalid recipient should be rejected");
    }

    // --- SUBPOLICY ---

    /// @notice Test recipient subpolicy mode - should pass when subpolicy approves
    function test_check1271SignedAction_recipient_subpolicy_approves_shouldPass() public {
        address recipient = makeAddr("recipient");
        uint256 targetChainId = 137;
        mockSubPolicy.setReturnValue(true);
        _initializePolicyWithRecipientSubpolicy(address(mockSubPolicy));

        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        uint256 fillExpiry = block.timestamp + 7200;
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 tokenOutHash = keccak256("tokenOut");

        bytes32 mandateHash = _computeMandateHash(
            recipient,
            targetChainId,
            fillExpiry,
            tokenOutHash,
            Constants.NO_OPS,
            Constants.NO_OPS,
            SAMPLE_QUALIFICATION_HASH
        );

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

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "Subpolicy approval should be allowed");
    }

    /// @notice Test recipient subpolicy mode - should fail when subpolicy rejects
    function test_check1271SignedAction_recipient_subpolicy_rejects_shouldFail() public {
        address recipient = makeAddr("recipient");
        uint256 targetChainId = 137;
        mockSubPolicy.setReturnValue(false);
        _initializePolicyWithRecipientSubpolicy(address(mockSubPolicy));

        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        uint256 fillExpiry = block.timestamp + 7200;
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 tokenOutHash = keccak256("tokenOut");

        bytes32 mandateHash = _computeMandateHash(
            recipient,
            targetChainId,
            fillExpiry,
            tokenOutHash,
            Constants.NO_OPS,
            Constants.NO_OPS,
            SAMPLE_QUALIFICATION_HASH
        );

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

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertFalse(result, "Subpolicy rejection should be rejected");
    }

    //-------------------------------------
    // 4b) RECIPIENT IS SPONSOR
    //-------------------------------------

    // --- SKIP ---

    /// @notice Test recipientIsSponsor SKIP mode - should pass when recipient differs from sponsor
    function test_check1271SignedAction_recipientIsSponsor_skip_shouldPass() public {
        // No initialization - defaults to SKIP
        address differentRecipient = makeAddr("differentRecipient");
        uint256 targetChainId = 137;

        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        uint256 fillExpiry = block.timestamp + 7200;
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 tokenOutHash = keccak256("tokenOut");

        bytes32 mandateHash = _computeMandateHash(
            differentRecipient,
            targetChainId,
            fillExpiry,
            tokenOutHash,
            Constants.NO_OPS,
            Constants.NO_OPS,
            SAMPLE_QUALIFICATION_HASH
        );

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            mandateHash
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "SKIP mode should allow different recipient");
    }

    // --- ENABLED (STORAGE) ---

    /// @notice Test recipientIsSponsor enabled - should pass when recipient equals sponsor
    function test_check1271SignedAction_recipientIsSponsor_enabled_valid_shouldPass() public {
        uint256 targetChainId = 137;
        _initializePolicyWithRecipientIsSponsor();

        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        uint256 fillExpiry = block.timestamp + 7200;
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 tokenOutHash = keccak256("tokenOut");

        // recipient = testAccount (the sponsor)
        bytes32 mandateHash = _computeMandateHash(
            testAccount,
            targetChainId,
            fillExpiry,
            tokenOutHash,
            Constants.NO_OPS,
            Constants.NO_OPS,
            SAMPLE_QUALIFICATION_HASH
        );

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            _createMandateWithTarget(
                testAccount,
                targetChainId,
                fillExpiry,
                tokenOutHash,
                Constants.NO_OPS,
                Constants.NO_OPS,
                SAMPLE_QUALIFICATION_HASH
            )
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "Action with recipient == sponsor should be allowed");
    }

    /// @notice Test recipientIsSponsor enabled - should fail when recipient does not equal sponsor
    function test_check1271SignedAction_recipientIsSponsor_enabled_invalid_shouldFail() public {
        address wrongRecipient = makeAddr("wrongRecipient");
        uint256 targetChainId = 137;
        _initializePolicyWithRecipientIsSponsor();

        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        uint256 fillExpiry = block.timestamp + 7200;
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 tokenOutHash = keccak256("tokenOut");

        bytes32 mandateHash = _computeMandateHash(
            wrongRecipient,
            targetChainId,
            fillExpiry,
            tokenOutHash,
            Constants.NO_OPS,
            Constants.NO_OPS,
            SAMPLE_QUALIFICATION_HASH
        );

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            _createMandateWithTarget(
                wrongRecipient,
                targetChainId,
                fillExpiry,
                tokenOutHash,
                Constants.NO_OPS,
                Constants.NO_OPS,
                SAMPLE_QUALIFICATION_HASH
            )
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertFalse(result, "Action with recipient != sponsor should be rejected");
    }

    //-------------------------------------
    // 5) FILL EXPIRY
    //-------------------------------------

    // --- SKIP ---

    /// @notice Test fillExpiry SKIP mode - should return true for any fillExpiry
    function test_check1271SignedAction_fillExpiry_skip_shouldReturnTrue() public {
        // No initialization - defaults to SKIP
        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 mandateHash = _computeBasicMandateHash();

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            mandateHash
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "SKIP mode should return true for any fillExpiry");
    }

    // --- STORAGE ---

    /// @notice Test fillExpiry storage mode - should pass when fillExpiry within bounds
    function test_check1271SignedAction_fillExpiry_storage_withinBounds_shouldPass() public {
        uint128 minExpiry = uint128(block.timestamp + 1000);
        uint128 maxExpiry = uint128(block.timestamp + 10_000);
        uint256 actualFillExpiry = block.timestamp + 5000;
        uint256 targetChainId = 137;
        _initializePolicyWithFillExpiry(minExpiry, maxExpiry, targetChainId);

        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        address recipient = makeAddr("recipient");
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 tokenOutHash = keccak256("tokenOut");

        bytes32 mandateHash = _computeMandateHash(
            recipient,
            targetChainId,
            actualFillExpiry,
            tokenOutHash,
            Constants.NO_OPS,
            Constants.NO_OPS,
            SAMPLE_QUALIFICATION_HASH
        );

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

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "Action with valid fillExpiry should be allowed");
    }

    /// @notice Test fillExpiry storage mode - should pass when fillExpiry equals min
    function test_check1271SignedAction_fillExpiry_storage_equalsMin_shouldPass() public {
        uint128 minExpiry = uint128(block.timestamp + 1000);
        uint128 maxExpiry = uint128(block.timestamp + 10_000);
        uint256 targetChainId = 137;
        _initializePolicyWithFillExpiry(minExpiry, maxExpiry, targetChainId);

        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        address recipient = makeAddr("recipient");
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 tokenOutHash = keccak256("tokenOut");

        bytes32 mandateHash = _computeMandateHash(
            recipient,
            targetChainId,
            uint256(minExpiry),
            tokenOutHash,
            Constants.NO_OPS,
            Constants.NO_OPS,
            SAMPLE_QUALIFICATION_HASH
        );

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            _createMandateWithTarget(
                recipient,
                targetChainId,
                uint256(minExpiry),
                tokenOutHash,
                Constants.NO_OPS,
                Constants.NO_OPS,
                SAMPLE_QUALIFICATION_HASH
            )
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "fillExpiry equals min should be allowed");
    }

    /// @notice Test fillExpiry storage mode - should pass when fillExpiry equals max
    function test_check1271SignedAction_fillExpiry_storage_equalsMax_shouldPass() public {
        uint128 minExpiry = uint128(block.timestamp + 1000);
        uint128 maxExpiry = uint128(block.timestamp + 10_000);
        uint256 targetChainId = 137;
        _initializePolicyWithFillExpiry(minExpiry, maxExpiry, targetChainId);

        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        address recipient = makeAddr("recipient");
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 tokenOutHash = keccak256("tokenOut");

        bytes32 mandateHash = _computeMandateHash(
            recipient,
            targetChainId,
            uint256(maxExpiry),
            tokenOutHash,
            Constants.NO_OPS,
            Constants.NO_OPS,
            SAMPLE_QUALIFICATION_HASH
        );

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            _createMandateWithTarget(
                recipient,
                targetChainId,
                uint256(maxExpiry),
                tokenOutHash,
                Constants.NO_OPS,
                Constants.NO_OPS,
                SAMPLE_QUALIFICATION_HASH
            )
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "fillExpiry equals max should be allowed");
    }

    /// @notice Test fillExpiry storage mode - should fail when fillExpiry below min
    function test_check1271SignedAction_fillExpiry_storage_belowMin_shouldFail() public {
        uint128 minExpiry = uint128(block.timestamp + 5000);
        uint128 maxExpiry = uint128(block.timestamp + 10_000);
        uint256 actualFillExpiry = block.timestamp + 1000;
        uint256 targetChainId = 137;
        _initializePolicyWithFillExpiry(minExpiry, maxExpiry, targetChainId);

        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        address recipient = makeAddr("recipient");
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 tokenOutHash = keccak256("tokenOut");

        bytes32 mandateHash = _computeMandateHash(
            recipient,
            targetChainId,
            actualFillExpiry,
            tokenOutHash,
            Constants.NO_OPS,
            Constants.NO_OPS,
            SAMPLE_QUALIFICATION_HASH
        );

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

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertFalse(result, "Action with fillExpiry below min should be rejected");
    }

    /// @notice Test fillExpiry storage mode - should fail when fillExpiry above max
    function test_check1271SignedAction_fillExpiry_storage_aboveMax_shouldFail() public {
        uint128 minExpiry = uint128(block.timestamp + 1000);
        uint128 maxExpiry = uint128(block.timestamp + 5000);
        uint256 actualFillExpiry = block.timestamp + 10_000;
        uint256 targetChainId = 137;
        _initializePolicyWithFillExpiry(minExpiry, maxExpiry, targetChainId);

        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        address recipient = makeAddr("recipient");
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 tokenOutHash = keccak256("tokenOut");

        bytes32 mandateHash = _computeMandateHash(
            recipient,
            targetChainId,
            actualFillExpiry,
            tokenOutHash,
            Constants.NO_OPS,
            Constants.NO_OPS,
            SAMPLE_QUALIFICATION_HASH
        );

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

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertFalse(result, "Action with fillExpiry above max should be rejected");
    }

    // --- SUBPOLICY ---

    /// @notice Test fillExpiry subpolicy mode - should pass when subpolicy approves
    function test_check1271SignedAction_fillExpiry_subpolicy_approves_shouldPass() public {
        uint256 targetChainId = 137;
        mockSubPolicy.setReturnValue(true);
        _initializePolicyWithFillExpirySubpolicy(address(mockSubPolicy));

        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        uint256 fillExpiry = block.timestamp + 5000;
        address recipient = makeAddr("recipient");
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 tokenOutHash = keccak256("tokenOut");

        bytes32 mandateHash = _computeMandateHash(
            recipient,
            targetChainId,
            fillExpiry,
            tokenOutHash,
            Constants.NO_OPS,
            Constants.NO_OPS,
            SAMPLE_QUALIFICATION_HASH
        );

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

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "Subpolicy approval should be allowed");
    }

    /// @notice Test fillExpiry subpolicy mode - should fail when subpolicy rejects
    function test_check1271SignedAction_fillExpiry_subpolicy_rejects_shouldFail() public {
        uint256 targetChainId = 137;
        mockSubPolicy.setReturnValue(false);
        _initializePolicyWithFillExpirySubpolicy(address(mockSubPolicy));

        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        uint256 fillExpiry = block.timestamp + 5000;
        address recipient = makeAddr("recipient");
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 tokenOutHash = keccak256("tokenOut");

        bytes32 mandateHash = _computeMandateHash(
            recipient,
            targetChainId,
            fillExpiry,
            tokenOutHash,
            Constants.NO_OPS,
            Constants.NO_OPS,
            SAMPLE_QUALIFICATION_HASH
        );

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

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertFalse(result, "Subpolicy rejection should be rejected");
    }

    //-------------------------------------
    // 6) TOKEN OUT
    //-------------------------------------

    // --- SKIP ---

    /// @notice Test tokenOut SKIP mode - should return true for any tokenOut
    function test_check1271SignedAction_tokenOut_skip_shouldReturnTrue() public {
        // No initialization - defaults to SKIP
        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 mandateHash = _computeBasicMandateHash();

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            mandateHash
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "SKIP mode should return true for any tokenOut");
    }

    // --- STORAGE ---

    /// @notice Test tokenOut storage mode - should pass when all tokens whitelisted
    function test_check1271SignedAction_tokenOut_storage_valid_shouldPass() public {
        address testToken = makeAddr("testToken");
        uint256 amount = 500;
        uint256 targetChainId = 137;
        _initializePolicyWithTokenOut(testToken, targetChainId, MODE_CHECK_STORAGE);

        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        uint256 fillExpiry = block.timestamp + 7200;
        address recipient = makeAddr("recipient");
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");

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

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "Action with valid tokenOut should be allowed");
    }

    /// @notice Test tokenOut storage mode - should fail when any token not whitelisted
    function test_check1271SignedAction_tokenOut_storage_invalid_shouldFail() public {
        address allowedToken = makeAddr("allowedToken");
        address usedToken = makeAddr("usedToken");
        uint256 amount = 500;
        uint256 targetChainId = 137;
        _initializePolicyWithTokenOut(allowedToken, targetChainId, MODE_CHECK_STORAGE);

        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        uint256 fillExpiry = block.timestamp + 7200;
        address recipient = makeAddr("recipient");
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");

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

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertFalse(result, "Action with invalid tokenOut should be rejected");
    }

    /// @notice Test tokenOut storage mode - should pass when multiple tokens whitelisted
    function test_check1271SignedAction_tokenOut_storage_multipleWhitelisted_shouldPass() public {
        address token1 = makeAddr("token1");
        address token2 = makeAddr("token2");
        uint256 amount = 500;
        uint256 targetChainId = 137;
        _initializePolicyWithMultipleTokensOut(token1, token2, targetChainId, MODE_CHECK_STORAGE);

        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        uint256 fillExpiry = block.timestamp + 7200;
        address recipient = makeAddr("recipient");
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");

        // Use second token
        bytes32 tokenOutHash = _computeTokenOutHash(token2, amount);
        bytes32 mandateHash = _computeMandateHash(
            recipient,
            targetChainId,
            fillExpiry,
            tokenOutHash,
            Constants.NO_OPS,
            Constants.NO_OPS,
            SAMPLE_QUALIFICATION_HASH
        );

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            _createMandateWithTokenOut(
                recipient,
                targetChainId,
                fillExpiry,
                token2,
                amount,
                Constants.NO_OPS,
                Constants.NO_OPS,
                SAMPLE_QUALIFICATION_HASH
            )
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "Second whitelisted token should be allowed");
    }

    // --- CATCHALL ---

    /// @notice Test tokenOut catchall mode - should pass when all tokens in catchall whitelist
    function test_check1271SignedAction_tokenOut_catchall_valid_shouldPass() public {
        address testToken = makeAddr("testToken");
        uint256 amount = 500;
        uint256 targetChainId = 137;
        _initializePolicyWithTokenOut(testToken, targetChainId, MODE_CHECK_CATCHALL);

        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        uint256 fillExpiry = block.timestamp + 7200;
        address recipient = makeAddr("recipient");
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");

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

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "Catchall valid tokenOut should be allowed");
    }

    /// @notice Test tokenOut catchall mode - should fail when any token not in catchall whitelist
    function test_check1271SignedAction_tokenOut_catchall_invalid_shouldFail() public {
        address allowedToken = makeAddr("allowedToken");
        address usedToken = makeAddr("usedToken");
        uint256 amount = 500;
        uint256 targetChainId = 137;
        _initializePolicyWithTokenOut(allowedToken, targetChainId, MODE_CHECK_CATCHALL);

        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        uint256 fillExpiry = block.timestamp + 7200;
        address recipient = makeAddr("recipient");
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");

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

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertFalse(result, "Catchall invalid tokenOut should be rejected");
    }

    // --- SUBPOLICY ---

    /// @notice Test tokenOut subpolicy mode - should pass when subpolicy approves
    function test_check1271SignedAction_tokenOut_subpolicy_approves_shouldPass() public {
        address testToken = makeAddr("testToken");
        uint256 amount = 500;
        uint256 targetChainId = 137;
        mockSubPolicy.setReturnValue(true);
        _initializePolicyWithTokenOutSubpolicy(address(mockSubPolicy));

        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        uint256 fillExpiry = block.timestamp + 7200;
        address recipient = makeAddr("recipient");
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");

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

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "Subpolicy approval should be allowed");
    }

    /// @notice Test tokenOut subpolicy mode - should fail when subpolicy rejects
    function test_check1271SignedAction_tokenOut_subpolicy_rejects_shouldFail() public {
        address testToken = makeAddr("testToken");
        uint256 amount = 500;
        uint256 targetChainId = 137;
        mockSubPolicy.setReturnValue(false);
        _initializePolicyWithTokenOutSubpolicy(address(mockSubPolicy));

        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        uint256 fillExpiry = block.timestamp + 7200;
        address recipient = makeAddr("recipient");
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");

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

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertFalse(result, "Subpolicy rejection should be rejected");
    }

    //-------------------------------------
    // 7) ORIGIN OPS
    //-------------------------------------

    // --- SKIP ---

    /// @notice Test originOps SKIP mode - should return true for any originOps hash
    function test_check1271SignedAction_originOps_skip_shouldReturnTrue() public {
        // No initialization - defaults to SKIP
        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 mandateHash = _computeBasicMandateHash();

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            mandateHash
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "SKIP mode should return true for any originOps");
    }

    // --- STORAGE ---

    /// @notice Test originOps storage mode - should pass when required and ops present
    function test_check1271SignedAction_originOps_storage_requiredAndPresent_shouldPass() public {
        _initializePolicyWithOriginOps(true, block.chainid);

        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        address recipient = makeAddr("recipient");
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 tokenOutHash = keccak256("tokenOut");
        uint256 targetChainId = 137;
        uint256 fillExpiry = block.timestamp + 7200;

        bytes32 targetHash = EIP712TypeHashLib.hashTargetAttributesRaw(
            recipient, tokenOutHash, targetChainId, fillExpiry
        );

        bytes32 mandateHash = EIP712TypeHashLib.hashMandateRaw(
            targetHash,
            SAMPLE_MIN_GAS,
            SAMPLE_OPS_HASH, // originOps present
            Constants.NO_OPS,
            SAMPLE_QUALIFICATION_HASH
        );

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            targetHash,
            targetChainId,
            SAMPLE_MIN_GAS,
            SAMPLE_OPS_HASH, // originOps present
            Constants.NO_OPS,
            SAMPLE_QUALIFICATION_HASH
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "Action with required originOps present should be allowed");
    }

    /// @notice Test originOps storage mode - should fail when required but ops missing
    function test_check1271SignedAction_originOps_storage_requiredButMissing_shouldFail() public {
        _initializePolicyWithOriginOps(true, block.chainid);

        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        address recipient = makeAddr("recipient");
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 tokenOutHash = keccak256("tokenOut");
        uint256 targetChainId = 137;
        uint256 fillExpiry = block.timestamp + 7200;

        bytes32 targetHash = EIP712TypeHashLib.hashTargetAttributesRaw(
            recipient, tokenOutHash, targetChainId, fillExpiry
        );

        bytes32 mandateHash = EIP712TypeHashLib.hashMandateRaw(
            targetHash,
            SAMPLE_MIN_GAS,
            Constants.NO_OPS, // originOps missing
            Constants.NO_OPS,
            SAMPLE_QUALIFICATION_HASH
        );

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            targetHash,
            targetChainId,
            SAMPLE_MIN_GAS,
            Constants.NO_OPS, // originOps missing
            Constants.NO_OPS,
            SAMPLE_QUALIFICATION_HASH
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertFalse(result, "Action with required but missing originOps should be rejected");
    }

    /// @notice Test originOps storage mode - should pass when not required and ops missing
    function test_check1271SignedAction_originOps_storage_notRequiredAndMissing_shouldPass()
        public
    {
        _initializePolicyWithOriginOps(false, block.chainid);

        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        address recipient = makeAddr("recipient");
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 tokenOutHash = keccak256("tokenOut");
        uint256 targetChainId = 137;
        uint256 fillExpiry = block.timestamp + 7200;

        bytes32 targetHash = EIP712TypeHashLib.hashTargetAttributesRaw(
            recipient, tokenOutHash, targetChainId, fillExpiry
        );

        bytes32 mandateHash = EIP712TypeHashLib.hashMandateRaw(
            targetHash,
            SAMPLE_MIN_GAS,
            Constants.NO_OPS, // originOps missing
            Constants.NO_OPS,
            SAMPLE_QUALIFICATION_HASH
        );

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            targetHash,
            targetChainId,
            SAMPLE_MIN_GAS,
            Constants.NO_OPS, // originOps missing
            Constants.NO_OPS,
            SAMPLE_QUALIFICATION_HASH
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "Action with not required and missing originOps should be allowed");
    }

    /// @notice Test originOps storage mode - should fail when not required but ops present
    function test_check1271SignedAction_originOps_storage_notRequiredButPresent_shouldFail()
        public
    {
        _initializePolicyWithOriginOps(false, block.chainid);

        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        address recipient = makeAddr("recipient");
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 tokenOutHash = keccak256("tokenOut");
        uint256 targetChainId = 137;
        uint256 fillExpiry = block.timestamp + 7200;

        bytes32 targetHash = EIP712TypeHashLib.hashTargetAttributesRaw(
            recipient, tokenOutHash, targetChainId, fillExpiry
        );

        bytes32 mandateHash = EIP712TypeHashLib.hashMandateRaw(
            targetHash,
            SAMPLE_MIN_GAS,
            SAMPLE_OPS_HASH, // originOps present
            Constants.NO_OPS,
            SAMPLE_QUALIFICATION_HASH
        );

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            targetHash,
            targetChainId,
            SAMPLE_MIN_GAS,
            SAMPLE_OPS_HASH, // originOps present
            Constants.NO_OPS,
            SAMPLE_QUALIFICATION_HASH
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertFalse(result, "Action with not required but present originOps should be rejected");
    }

    // --- CATCHALL ---

    /// @notice Test originOps catchall mode - should pass when catchall config satisfied
    function test_check1271SignedAction_originOps_catchall_satisfied_shouldPass() public {
        _initializePolicyWithOriginOpsCatchall(true);

        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        address recipient = makeAddr("recipient");
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 tokenOutHash = keccak256("tokenOut");
        uint256 targetChainId = 137;
        uint256 fillExpiry = block.timestamp + 7200;

        bytes32 targetHash = EIP712TypeHashLib.hashTargetAttributesRaw(
            recipient, tokenOutHash, targetChainId, fillExpiry
        );

        bytes32 mandateHash = EIP712TypeHashLib.hashMandateRaw(
            targetHash,
            SAMPLE_MIN_GAS,
            SAMPLE_OPS_HASH, // originOps present
            Constants.NO_OPS,
            SAMPLE_QUALIFICATION_HASH
        );

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            targetHash,
            targetChainId,
            SAMPLE_MIN_GAS,
            SAMPLE_OPS_HASH, // originOps present
            Constants.NO_OPS,
            SAMPLE_QUALIFICATION_HASH
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "Catchall satisfied originOps should be allowed");
    }

    /// @notice Test originOps catchall mode - should fail when catchall config not satisfied
    function test_check1271SignedAction_originOps_catchall_notSatisfied_shouldFail() public {
        _initializePolicyWithOriginOpsCatchall(true);

        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        address recipient = makeAddr("recipient");
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 tokenOutHash = keccak256("tokenOut");
        uint256 targetChainId = 137;
        uint256 fillExpiry = block.timestamp + 7200;

        bytes32 targetHash = EIP712TypeHashLib.hashTargetAttributesRaw(
            recipient, tokenOutHash, targetChainId, fillExpiry
        );

        bytes32 mandateHash = EIP712TypeHashLib.hashMandateRaw(
            targetHash,
            SAMPLE_MIN_GAS,
            Constants.NO_OPS, // originOps missing
            Constants.NO_OPS,
            SAMPLE_QUALIFICATION_HASH
        );

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            targetHash,
            targetChainId,
            SAMPLE_MIN_GAS,
            Constants.NO_OPS, // originOps missing
            Constants.NO_OPS,
            SAMPLE_QUALIFICATION_HASH
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertFalse(result, "Catchall not satisfied originOps should be rejected");
    }

    // --- SUBPOLICY ---

    /// @notice Test originOps subpolicy mode - should pass when subpolicy approves
    function test_check1271SignedAction_originOps_subpolicy_approves_shouldPass() public {
        mockSubPolicy.setReturnValue(true);
        _initializePolicyWithOriginOpsSubpolicy(address(mockSubPolicy));

        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        address recipient = makeAddr("recipient");
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 tokenOutHash = keccak256("tokenOut");
        uint256 targetChainId = 137;
        uint256 fillExpiry = block.timestamp + 7200;

        bytes32 targetHash = EIP712TypeHashLib.hashTargetAttributesRaw(
            recipient, tokenOutHash, targetChainId, fillExpiry
        );

        bytes32 mandateHash = EIP712TypeHashLib.hashMandateRaw(
            targetHash, SAMPLE_MIN_GAS, SAMPLE_OPS_HASH, Constants.NO_OPS, SAMPLE_QUALIFICATION_HASH
        );

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            targetHash,
            targetChainId,
            SAMPLE_MIN_GAS,
            SAMPLE_OPS_HASH,
            Constants.NO_OPS,
            SAMPLE_QUALIFICATION_HASH
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "Subpolicy approval should be allowed");
    }

    /// @notice Test originOps subpolicy mode - should fail when subpolicy rejects
    function test_check1271SignedAction_originOps_subpolicy_rejects_shouldFail() public {
        mockSubPolicy.setReturnValue(false);
        _initializePolicyWithOriginOpsSubpolicy(address(mockSubPolicy));

        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        address recipient = makeAddr("recipient");
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 tokenOutHash = keccak256("tokenOut");
        uint256 targetChainId = 137;
        uint256 fillExpiry = block.timestamp + 7200;

        bytes32 targetHash = EIP712TypeHashLib.hashTargetAttributesRaw(
            recipient, tokenOutHash, targetChainId, fillExpiry
        );

        bytes32 mandateHash = EIP712TypeHashLib.hashMandateRaw(
            targetHash, SAMPLE_MIN_GAS, SAMPLE_OPS_HASH, Constants.NO_OPS, SAMPLE_QUALIFICATION_HASH
        );

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            targetHash,
            targetChainId,
            SAMPLE_MIN_GAS,
            SAMPLE_OPS_HASH,
            Constants.NO_OPS,
            SAMPLE_QUALIFICATION_HASH
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertFalse(result, "Subpolicy rejection should be rejected");
    }

    //-------------------------------------
    // 8) DEST OPS
    //-------------------------------------

    // --- SKIP ---

    /// @notice Test destOps SKIP mode - should return true for any destOps hash
    function test_check1271SignedAction_destOps_skip_shouldReturnTrue() public {
        // No initialization - defaults to SKIP
        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 mandateHash = _computeBasicMandateHash();

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            mandateHash
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "SKIP mode should return true for any destOps");
    }

    // --- STORAGE ---

    /// @notice Test destOps storage mode - should pass when required and ops present
    function test_check1271SignedAction_destOps_storage_requiredAndPresent_shouldPass() public {
        uint256 targetChainId = 137;
        _initializePolicyWithDestOps(true, targetChainId);

        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        address recipient = testAccount; // recipient == sponsor (satisfies recipientIsSponsor)
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 tokenOutHash = keccak256("tokenOut");
        uint256 fillExpiry = block.timestamp + 7200;

        bytes32 targetHash = EIP712TypeHashLib.hashTargetAttributesRaw(
            recipient, tokenOutHash, targetChainId, fillExpiry
        );

        bytes32 mandateHash = EIP712TypeHashLib.hashMandateRaw(
            targetHash,
            SAMPLE_MIN_GAS,
            Constants.NO_OPS,
            SAMPLE_OPS_HASH, // destOps present
            SAMPLE_QUALIFICATION_HASH
        );

        // Expanded target (recipient, targetChainId, fillExpiry, tokenOutHash) so targetChainId is bound
        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            recipient,
            targetChainId,
            fillExpiry,
            tokenOutHash,
            SAMPLE_MIN_GAS,
            Constants.NO_OPS,
            SAMPLE_OPS_HASH, // destOps present
            SAMPLE_QUALIFICATION_HASH
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "Action with required destOps present should be allowed");
    }

    /// @notice Test destOps storage mode - should fail when required but ops missing
    function test_check1271SignedAction_destOps_storage_requiredButMissing_shouldFail() public {
        uint256 targetChainId = 137;
        _initializePolicyWithDestOps(true, targetChainId);

        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        address recipient = testAccount; // recipient == sponsor (satisfies recipientIsSponsor)
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 tokenOutHash = keccak256("tokenOut");
        uint256 fillExpiry = block.timestamp + 7200;

        bytes32 targetHash = EIP712TypeHashLib.hashTargetAttributesRaw(
            recipient, tokenOutHash, targetChainId, fillExpiry
        );

        bytes32 mandateHash = EIP712TypeHashLib.hashMandateRaw(
            targetHash,
            SAMPLE_MIN_GAS,
            Constants.NO_OPS,
            Constants.NO_OPS, // destOps missing
            SAMPLE_QUALIFICATION_HASH
        );

        // Expanded target (recipient, targetChainId, fillExpiry, tokenOutHash) so targetChainId is bound
        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            recipient,
            targetChainId,
            fillExpiry,
            tokenOutHash,
            SAMPLE_MIN_GAS,
            Constants.NO_OPS,
            Constants.NO_OPS, // destOps missing
            SAMPLE_QUALIFICATION_HASH
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertFalse(result, "Action with required but missing destOps should be rejected");
    }

    /// @notice Test destOps storage mode - should pass when not required and ops missing
    function test_check1271SignedAction_destOps_storage_notRequiredAndMissing_shouldPass() public {
        uint256 targetChainId = 137;
        _initializePolicyWithDestOps(false, targetChainId);

        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        address recipient = testAccount; // recipient == sponsor (satisfies recipientIsSponsor)
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 tokenOutHash = keccak256("tokenOut");
        uint256 fillExpiry = block.timestamp + 7200;

        bytes32 targetHash = EIP712TypeHashLib.hashTargetAttributesRaw(
            recipient, tokenOutHash, targetChainId, fillExpiry
        );

        bytes32 mandateHash = EIP712TypeHashLib.hashMandateRaw(
            targetHash,
            SAMPLE_MIN_GAS,
            Constants.NO_OPS,
            Constants.NO_OPS, // destOps missing
            SAMPLE_QUALIFICATION_HASH
        );

        // Expanded target (recipient, targetChainId, fillExpiry, tokenOutHash) so targetChainId is bound
        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            recipient,
            targetChainId,
            fillExpiry,
            tokenOutHash,
            SAMPLE_MIN_GAS,
            Constants.NO_OPS,
            Constants.NO_OPS, // destOps missing
            SAMPLE_QUALIFICATION_HASH
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "Action with not required and missing destOps should be allowed");
    }

    /// @notice Test destOps storage mode - should fail when not required but ops present
    function test_check1271SignedAction_destOps_storage_notRequiredButPresent_shouldFail() public {
        uint256 targetChainId = 137;
        _initializePolicyWithDestOps(false, targetChainId);

        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        address recipient = testAccount; // recipient == sponsor (satisfies recipientIsSponsor)
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 tokenOutHash = keccak256("tokenOut");
        uint256 fillExpiry = block.timestamp + 7200;

        bytes32 targetHash = EIP712TypeHashLib.hashTargetAttributesRaw(
            recipient, tokenOutHash, targetChainId, fillExpiry
        );

        bytes32 mandateHash = EIP712TypeHashLib.hashMandateRaw(
            targetHash,
            SAMPLE_MIN_GAS,
            Constants.NO_OPS,
            SAMPLE_OPS_HASH, // destOps present
            SAMPLE_QUALIFICATION_HASH
        );

        // Expanded target (recipient, targetChainId, fillExpiry, tokenOutHash) so targetChainId is bound
        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            recipient,
            targetChainId,
            fillExpiry,
            tokenOutHash,
            SAMPLE_MIN_GAS,
            Constants.NO_OPS,
            SAMPLE_OPS_HASH, // destOps present
            SAMPLE_QUALIFICATION_HASH
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertFalse(result, "Action with not required but present destOps should be rejected");
    }

    // --- CATCHALL ---

    /// @notice Test destOps catchall mode - should pass when catchall config satisfied
    function test_check1271SignedAction_destOps_catchall_satisfied_shouldPass() public {
        _initializePolicyWithDestOpsCatchall(true);

        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        address recipient = makeAddr("recipient");
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 tokenOutHash = keccak256("tokenOut");
        uint256 targetChainId = 137;
        uint256 fillExpiry = block.timestamp + 7200;

        bytes32 targetHash = EIP712TypeHashLib.hashTargetAttributesRaw(
            recipient, tokenOutHash, targetChainId, fillExpiry
        );

        bytes32 mandateHash = EIP712TypeHashLib.hashMandateRaw(
            targetHash,
            SAMPLE_MIN_GAS,
            Constants.NO_OPS,
            SAMPLE_OPS_HASH, // destOps present
            SAMPLE_QUALIFICATION_HASH
        );

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            targetHash,
            targetChainId,
            SAMPLE_MIN_GAS,
            Constants.NO_OPS,
            SAMPLE_OPS_HASH, // destOps present
            SAMPLE_QUALIFICATION_HASH
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "Catchall satisfied destOps should be allowed");
    }

    /// @notice Test destOps catchall mode - should fail when catchall config not satisfied
    function test_check1271SignedAction_destOps_catchall_notSatisfied_shouldFail() public {
        _initializePolicyWithDestOpsCatchall(true);

        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        address recipient = makeAddr("recipient");
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 tokenOutHash = keccak256("tokenOut");
        uint256 targetChainId = 137;
        uint256 fillExpiry = block.timestamp + 7200;

        bytes32 targetHash = EIP712TypeHashLib.hashTargetAttributesRaw(
            recipient, tokenOutHash, targetChainId, fillExpiry
        );

        bytes32 mandateHash = EIP712TypeHashLib.hashMandateRaw(
            targetHash,
            SAMPLE_MIN_GAS,
            Constants.NO_OPS,
            Constants.NO_OPS, // destOps missing
            SAMPLE_QUALIFICATION_HASH
        );

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            targetHash,
            targetChainId,
            SAMPLE_MIN_GAS,
            Constants.NO_OPS,
            Constants.NO_OPS, // destOps missing
            SAMPLE_QUALIFICATION_HASH
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertFalse(result, "Catchall not satisfied destOps should be rejected");
    }

    // --- SUBPOLICY ---

    /// @notice Test destOps subpolicy mode - should pass when subpolicy approves
    function test_check1271SignedAction_destOps_subpolicy_approves_shouldPass() public {
        mockSubPolicy.setReturnValue(true);
        _initializePolicyWithDestOpsSubpolicy(address(mockSubPolicy));

        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        address recipient = testAccount; // recipient == sponsor (satisfies recipientIsSponsor)
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 tokenOutHash = keccak256("tokenOut");
        uint256 targetChainId = 137;
        uint256 fillExpiry = block.timestamp + 7200;

        bytes32 targetHash = EIP712TypeHashLib.hashTargetAttributesRaw(
            recipient, tokenOutHash, targetChainId, fillExpiry
        );

        bytes32 mandateHash = EIP712TypeHashLib.hashMandateRaw(
            targetHash, SAMPLE_MIN_GAS, Constants.NO_OPS, SAMPLE_OPS_HASH, SAMPLE_QUALIFICATION_HASH
        );

        // Expanded target (recipient, targetChainId, fillExpiry, tokenOutHash) so targetChainId is bound
        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            recipient,
            targetChainId,
            fillExpiry,
            tokenOutHash,
            SAMPLE_MIN_GAS,
            Constants.NO_OPS,
            SAMPLE_OPS_HASH,
            SAMPLE_QUALIFICATION_HASH
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "Subpolicy approval should be allowed");
    }

    /// @notice Test destOps subpolicy mode - should fail when subpolicy rejects
    function test_check1271SignedAction_destOps_subpolicy_rejects_shouldFail() public {
        mockSubPolicy.setReturnValue(false);
        _initializePolicyWithDestOpsSubpolicy(address(mockSubPolicy));

        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        address recipient = testAccount; // recipient == sponsor (satisfies recipientIsSponsor)
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 tokenOutHash = keccak256("tokenOut");
        uint256 targetChainId = 137;
        uint256 fillExpiry = block.timestamp + 7200;

        bytes32 targetHash = EIP712TypeHashLib.hashTargetAttributesRaw(
            recipient, tokenOutHash, targetChainId, fillExpiry
        );

        bytes32 mandateHash = EIP712TypeHashLib.hashMandateRaw(
            targetHash, SAMPLE_MIN_GAS, Constants.NO_OPS, SAMPLE_OPS_HASH, SAMPLE_QUALIFICATION_HASH
        );

        // Expanded target (recipient, targetChainId, fillExpiry, tokenOutHash) so targetChainId is bound
        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            recipient,
            targetChainId,
            fillExpiry,
            tokenOutHash,
            SAMPLE_MIN_GAS,
            Constants.NO_OPS,
            SAMPLE_OPS_HASH,
            SAMPLE_QUALIFICATION_HASH
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertFalse(result, "Subpolicy rejection should be rejected");
    }

    //-------------------------------------
    // 9) QUALIFICATION
    //-------------------------------------

    // --- SKIP ---

    /// @notice Test qualification SKIP mode - should return true for any qualification
    function test_check1271SignedAction_qualification_skip_shouldReturnTrue() public {
        // No initialization - defaults to SKIP
        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 mandateHash = _computeBasicMandateHash();

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            mandateHash
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "SKIP mode should return true for any qualification");
    }

    // --- STORAGE ---

    /// @notice Test qualification storage mode - should pass when qualification passes rules
    function test_check1271SignedAction_qualification_storage_valid_shouldPass() public {
        uint64 offset = 0;
        bytes32 expectedValue = bytes32(uint256(0x123));
        (address arbiter,) = makeAddrAndKey("arbiter");
        _initializePolicyWithQualification(arbiter, block.chainid, offset, expectedValue);

        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        address recipient = makeAddr("recipient");
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 tokenOutHash = keccak256("tokenOut");
        uint256 targetChainId = 137;
        uint256 fillExpiry = block.timestamp + 7200;

        bytes memory qualificationData = abi.encodePacked(expectedValue);
        bytes32 qualificationHash = keccak256(qualificationData);

        bytes32 targetHash = EIP712TypeHashLib.hashTargetAttributesRaw(
            recipient, tokenOutHash, targetChainId, fillExpiry
        );

        bytes32 mandateHash = EIP712TypeHashLib.hashMandateRaw(
            targetHash, SAMPLE_MIN_GAS, Constants.NO_OPS, Constants.NO_OPS, qualificationHash
        );

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            targetHash,
            targetChainId,
            SAMPLE_MIN_GAS,
            Constants.NO_OPS,
            Constants.NO_OPS,
            uint256(qualificationData.length),
            qualificationData
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "Action with valid qualification should be allowed");
    }

    /// @notice Test qualification storage mode - should fail when qualification fails rules
    function test_check1271SignedAction_qualification_storage_invalid_shouldFail() public {
        uint64 offset = 0;
        bytes32 expectedValue = bytes32(uint256(0x123));
        bytes32 wrongValue = bytes32(uint256(0x456));
        (address arbiter,) = makeAddrAndKey("arbiter");
        _initializePolicyWithQualification(arbiter, block.chainid, offset, expectedValue);

        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        address recipient = makeAddr("recipient");
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 tokenOutHash = keccak256("tokenOut");
        uint256 targetChainId = 137;
        uint256 fillExpiry = block.timestamp + 7200;

        bytes memory qualificationData = abi.encodePacked(wrongValue);
        bytes32 qualificationHash = keccak256(qualificationData);

        bytes32 targetHash = EIP712TypeHashLib.hashTargetAttributesRaw(
            recipient, tokenOutHash, targetChainId, fillExpiry
        );

        bytes32 mandateHash = EIP712TypeHashLib.hashMandateRaw(
            targetHash, SAMPLE_MIN_GAS, Constants.NO_OPS, Constants.NO_OPS, qualificationHash
        );

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            targetHash,
            targetChainId,
            SAMPLE_MIN_GAS,
            Constants.NO_OPS,
            Constants.NO_OPS,
            uint256(qualificationData.length),
            qualificationData
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertFalse(result, "Action with invalid qualification should be rejected");
    }

    // --- CATCHALL ---

    /// @notice Test qualification catchall mode - should pass when catchall rules pass
    function test_check1271SignedAction_qualification_catchall_valid_shouldPass() public {
        uint64 offset = 0;
        bytes32 expectedValue = bytes32(uint256(0x123));
        (address arbiter,) = makeAddrAndKey("arbiter");
        _initializePolicyWithQualificationCatchall(arbiter, offset, expectedValue);

        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        address recipient = makeAddr("recipient");
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 tokenOutHash = keccak256("tokenOut");
        uint256 targetChainId = 137;
        uint256 fillExpiry = block.timestamp + 7200;

        bytes memory qualificationData = abi.encodePacked(expectedValue);
        bytes32 qualificationHash = keccak256(qualificationData);

        bytes32 targetHash = EIP712TypeHashLib.hashTargetAttributesRaw(
            recipient, tokenOutHash, targetChainId, fillExpiry
        );

        bytes32 mandateHash = EIP712TypeHashLib.hashMandateRaw(
            targetHash, SAMPLE_MIN_GAS, Constants.NO_OPS, Constants.NO_OPS, qualificationHash
        );

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            targetHash,
            targetChainId,
            SAMPLE_MIN_GAS,
            Constants.NO_OPS,
            Constants.NO_OPS,
            uint256(qualificationData.length),
            qualificationData
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "Catchall valid qualification should be allowed");
    }

    /// @notice Test qualification catchall mode - should fail when catchall rules fail
    function test_check1271SignedAction_qualification_catchall_invalid_shouldFail() public {
        uint64 offset = 0;
        bytes32 expectedValue = bytes32(uint256(0x123));
        bytes32 wrongValue = bytes32(uint256(0x456));
        (address arbiter,) = makeAddrAndKey("arbiter");
        _initializePolicyWithQualificationCatchall(arbiter, offset, expectedValue);

        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        address recipient = makeAddr("recipient");
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 tokenOutHash = keccak256("tokenOut");
        uint256 targetChainId = 137;
        uint256 fillExpiry = block.timestamp + 7200;

        bytes memory qualificationData = abi.encodePacked(wrongValue);
        bytes32 qualificationHash = keccak256(qualificationData);

        bytes32 targetHash = EIP712TypeHashLib.hashTargetAttributesRaw(
            recipient, tokenOutHash, targetChainId, fillExpiry
        );

        bytes32 mandateHash = EIP712TypeHashLib.hashMandateRaw(
            targetHash, SAMPLE_MIN_GAS, Constants.NO_OPS, Constants.NO_OPS, qualificationHash
        );

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            targetHash,
            targetChainId,
            SAMPLE_MIN_GAS,
            Constants.NO_OPS,
            Constants.NO_OPS,
            uint256(qualificationData.length),
            qualificationData
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertFalse(result, "Catchall invalid qualification should be rejected");
    }

    // --- SUBPOLICY ---

    /// @notice Test qualification subpolicy mode - should pass when subpolicy approves
    function test_check1271SignedAction_qualification_subpolicy_approves_shouldPass() public {
        mockSubPolicy.setReturnValue(true);
        _initializePolicyWithQualificationSubpolicy(address(mockSubPolicy));

        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        address recipient = makeAddr("recipient");
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 tokenOutHash = keccak256("tokenOut");
        uint256 targetChainId = 137;
        uint256 fillExpiry = block.timestamp + 7200;

        bytes memory qualificationData = abi.encodePacked(bytes32(uint256(0x123)));
        bytes32 qualificationHash = keccak256(qualificationData);

        bytes32 targetHash = EIP712TypeHashLib.hashTargetAttributesRaw(
            recipient, tokenOutHash, targetChainId, fillExpiry
        );

        bytes32 mandateHash = EIP712TypeHashLib.hashMandateRaw(
            targetHash, SAMPLE_MIN_GAS, Constants.NO_OPS, Constants.NO_OPS, qualificationHash
        );

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            targetHash,
            targetChainId,
            SAMPLE_MIN_GAS,
            Constants.NO_OPS,
            Constants.NO_OPS,
            uint8(0), // flags
            uint256(qualificationData.length),
            qualificationData
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "Subpolicy approval should be allowed");
    }

    /// @notice Test qualification subpolicy mode - should fail when subpolicy rejects
    function test_check1271SignedAction_qualification_subpolicy_rejects_shouldFail() public {
        mockSubPolicy.setReturnValue(false);
        _initializePolicyWithQualificationSubpolicy(address(mockSubPolicy));

        (address arbiter,) = makeAddrAndKey("arbiter");
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        address recipient = makeAddr("recipient");
        bytes32 tokenPermissionsHash = keccak256("tokenPermissions");
        bytes32 tokenOutHash = keccak256("tokenOut");
        uint256 targetChainId = 137;
        uint256 fillExpiry = block.timestamp + 7200;

        bytes memory qualificationData = abi.encodePacked(bytes32(uint256(0x123)));
        bytes32 qualificationHash = keccak256(qualificationData);

        bytes32 targetHash = EIP712TypeHashLib.hashTargetAttributesRaw(
            recipient, tokenOutHash, targetChainId, fillExpiry
        );

        bytes32 mandateHash = EIP712TypeHashLib.hashMandateRaw(
            targetHash, SAMPLE_MIN_GAS, Constants.NO_OPS, Constants.NO_OPS, qualificationHash
        );

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsHash(tokenPermissionsHash),
            targetHash,
            targetChainId,
            SAMPLE_MIN_GAS,
            Constants.NO_OPS,
            Constants.NO_OPS,
            uint8(0), // flags
            uint256(qualificationData.length),
            qualificationData
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertFalse(result, "Subpolicy rejection should be rejected");
    }

    //-------------------------------------
    // 10) MULTIPLE FIELDS
    //-------------------------------------

    /// @notice Test multiple fields - should return true when all fields pass
    function test_check1271SignedAction_multipleFields_allPass_shouldReturnTrue() public {
        (address arbiter,) = makeAddrAndKey("arbiter");
        address testToken = makeAddr("testToken");
        uint256 amount = 1000;

        // Initialize with arbiter and tokenIn checks
        _initializePolicyWithMultipleFields(arbiter, testToken);

        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;

        bytes32 tokenPermissionsHash = _computeTokenPermissionsHash(testToken, amount);
        bytes32 mandateHash = _computeBasicMandateHash();

        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsArray(testToken, amount),
            mandateHash
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertTrue(result, "All fields passing should return true");
    }

    /// @notice Test multiple fields - should return false when first field fails
    function test_check1271SignedAction_multipleFields_firstFails_shouldReturnFalse() public {
        (address allowedArbiter,) = makeAddrAndKey("allowedArbiter");
        (address usedArbiter,) = makeAddrAndKey("usedArbiter");
        address testToken = makeAddr("testToken");
        uint256 amount = 1000;

        // Initialize with arbiter and tokenIn checks
        _initializePolicyWithMultipleFields(allowedArbiter, testToken);

        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;

        bytes32 tokenPermissionsHash = _computeTokenPermissionsHash(testToken, amount);
        bytes32 mandateHash = _computeBasicMandateHash();

        // Use wrong arbiter
        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(usedArbiter, nonce, deadline),
            _createTokenPermissionsArray(testToken, amount),
            mandateHash
        );

        bytes32 expectedHash =
            _computeExpectedHash(usedArbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertFalse(result, "First field failing should return false");
    }

    /// @notice Test multiple fields - should return false when middle field fails
    function test_check1271SignedAction_multipleFields_middleFails_shouldReturnFalse() public {
        (address arbiter,) = makeAddrAndKey("arbiter");
        address allowedToken = makeAddr("allowedToken");
        address usedToken = makeAddr("usedToken");
        uint256 amount = 1000;

        // Initialize with arbiter and tokenIn checks
        _initializePolicyWithMultipleFields(arbiter, allowedToken);

        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;

        bytes32 tokenPermissionsHash = _computeTokenPermissionsHash(usedToken, amount);
        bytes32 mandateHash = _computeBasicMandateHash();

        // Use wrong token
        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsArray(usedToken, amount),
            mandateHash
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertFalse(result, "Middle field failing should return false");
    }

    /// @notice Test multiple fields - should return false when last field fails
    function test_check1271SignedAction_multipleFields_lastFails_shouldReturnFalse() public {
        (address arbiter,) = makeAddrAndKey("arbiter");
        address testToken = makeAddr("testToken");
        address allowedRecipient = makeAddr("allowedRecipient");
        address usedRecipient = makeAddr("usedRecipient");
        uint256 amount = 1000;
        uint256 targetChainId = 137;

        // Initialize with arbiter, tokenIn, and recipient checks
        _initializePolicyWithThreeFields(arbiter, testToken, allowedRecipient, targetChainId);

        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 3600;
        uint256 fillExpiry = block.timestamp + 7200;
        bytes32 tokenOutHash = keccak256("tokenOut");

        bytes32 tokenPermissionsHash = _computeTokenPermissionsHash(testToken, amount);
        bytes32 mandateHash = _computeMandateHash(
            usedRecipient,
            targetChainId,
            fillExpiry,
            tokenOutHash,
            Constants.NO_OPS,
            Constants.NO_OPS,
            SAMPLE_QUALIFICATION_HASH
        );

        // Use wrong recipient
        bytes memory permit2Data = abi.encodePacked(
            _createPermit2Header(arbiter, nonce, deadline),
            _createTokenPermissionsArray(testToken, amount),
            _createMandateWithTarget(
                usedRecipient,
                targetChainId,
                fillExpiry,
                tokenOutHash,
                Constants.NO_OPS,
                Constants.NO_OPS,
                SAMPLE_QUALIFICATION_HASH
            )
        );

        bytes32 expectedHash =
            _computeExpectedHash(arbiter, nonce, deadline, tokenPermissionsHash, mandateHash);

        bool result = permit2ClaimPolicy.check1271SignedAction(
            testConfigId, admin.addr, testAccount, expectedHash, permit2Data
        );

        assertFalse(result, "Last field failing should return false");
    }

    /*//////////////////////////////////////////////////////////////
                                 HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Compute basic mandate hash
    function _computeBasicMandateHash() internal pure returns (bytes32) {
        return EIP712TypeHashLib.hashMandateRaw(
            keccak256("target"),
            SAMPLE_MIN_GAS,
            Constants.NO_OPS,
            Constants.NO_OPS,
            SAMPLE_QUALIFICATION_HASH
        );
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
        return abi.encodePacked(uint8(1), uint256(uint160(token)), amount);
    }

    /// @notice Creates mandate with target expanded
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
            recipient,
            targetChainId,
            fillExpiry,
            tokenOutHash,
            SAMPLE_MIN_GAS,
            originOpsHash,
            destOpsHash,
            qualificationHash
        );
    }

    /// @notice Creates mandate with tokenOut array
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
            recipient,
            targetChainId,
            fillExpiry,
            uint8(1),
            uint256(uint160(tokenOut)),
            tokenOutAmount,
            SAMPLE_MIN_GAS,
            originOpsHash,
            destOpsHash,
            qualificationHash
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

    /// @notice Computes tokenPermissions hash from token and amount
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
        return this.computeTokenPermissionsHashExternal(tokenPermissions);
    }

    /// @notice External helper for tokenPermissions hash (calldata)
    function computeTokenPermissionsHashExternal(uint256[2][] calldata tokenPermissions)
        external
        pure
        returns (bytes32)
    {
        return EIP712TypeHashLib.hashTokenPermissions(tokenPermissions);
    }

    /// @notice Computes tokenOut hash
    function _computeTokenOutHash(address token, uint256 amount) internal view returns (bytes32) {
        uint256[2][] memory tokenOut = new uint256[2][](1);
        tokenOut[0][0] = uint256(uint160(token));
        tokenOut[0][1] = amount;
        return this.computeTokenOutHashExternal(tokenOut);
    }

    /// @notice External helper for tokenOut hash (calldata)
    function computeTokenOutHashExternal(uint256[2][] calldata tokenOut)
        external
        pure
        returns (bytes32)
    {
        return EIP712TypeHashLib.hashTokenOut(tokenOut);
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

    /*//////////////////////////////////////////////////////////////
                            INITIALIZATION HELPERS
      //////////////////////////////////////////////////////////////*/

    /// @notice Initialize policy with arbiter check (STORAGE mode)
    function _initializePolicyWithArbiter(address arbiter, uint8 mode) internal {
        uint32 modeConfig = _createModeConfig(FIELD_ARBITER, mode);
        bytes memory initData = abi.encodePacked(modeConfig, uint8(1), arbiter);
        permit2ClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    /// @notice Initialize policy with multiple arbiters
    function _initializePolicyWithMultipleArbiters(
        address arbiter1,
        address arbiter2,
        uint8 mode
    )
        internal
    {
        uint32 modeConfig = _createModeConfig(FIELD_ARBITER, mode);
        bytes memory initData = abi.encodePacked(modeConfig, uint8(2), arbiter1, arbiter2);
        permit2ClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    /// @notice Initialize policy with arbiter subpolicy
    function _initializePolicyWithArbiterSubpolicy(address subpolicyAddr) internal {
        uint32 modeConfig = _createModeConfig(FIELD_ARBITER, MODE_CHECK_SUBPOLICY);
        bytes memory initData = abi.encodePacked(
            modeConfig,
            uint8(1), // count
            uint8(FIELD_ARBITER),
            subpolicyAddr,
            uint256(0) // initDataLength
        );
        permit2ClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    /// @notice Initialize policy with expiry check
    function _initializePolicyWithExpiry(uint128 min, uint128 max) internal {
        uint32 modeConfig = _createModeConfig(FIELD_EXPIRY, MODE_CHECK_STORAGE);
        bytes memory initData = abi.encodePacked(modeConfig, uint256(min) | (uint256(max) << 128));
        permit2ClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    /// @notice Initialize policy with expiry subpolicy
    function _initializePolicyWithExpirySubpolicy(address subpolicyAddr) internal {
        uint32 modeConfig = _createModeConfig(FIELD_EXPIRY, MODE_CHECK_SUBPOLICY);
        bytes memory initData = abi.encodePacked(
            modeConfig, uint8(1), uint8(FIELD_EXPIRY), subpolicyAddr, uint256(0)
        );
        permit2ClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    /// @notice Initialize policy with tokenIn check
    function _initializePolicyWithTokenIn(address token, uint8 mode) internal {
        uint32 modeConfig = _createModeConfig(FIELD_TOKEN_IN, mode);
        uint256 chainId = (mode == MODE_CHECK_CATCHALL) ? 0 : block.chainid;
        bytes memory initData = abi.encodePacked(modeConfig, uint8(1), chainId, token);
        permit2ClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    /// @notice Initialize policy with multiple tokens in
    function _initializePolicyWithMultipleTokensIn(
        address token1,
        address token2,
        uint8 mode
    )
        internal
    {
        uint32 modeConfig = _createModeConfig(FIELD_TOKEN_IN, mode);
        uint256 chainId = (mode == MODE_CHECK_CATCHALL) ? 0 : block.chainid;
        bytes memory initData =
            abi.encodePacked(modeConfig, uint8(2), chainId, token1, chainId, token2);
        permit2ClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    /// @notice Initialize policy with tokenIn subpolicy
    function _initializePolicyWithTokenInSubpolicy(address subpolicyAddr) internal {
        uint32 modeConfig = _createModeConfig(FIELD_TOKEN_IN, MODE_CHECK_SUBPOLICY);
        bytes memory initData = abi.encodePacked(
            modeConfig, uint8(1), uint8(FIELD_TOKEN_IN), subpolicyAddr, uint256(0)
        );
        permit2ClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    /// @notice Initialize policy with recipient check
    function _initializePolicyWithRecipient(
        address recipient,
        uint256 targetChainId,
        uint8 mode
    )
        internal
    {
        uint32 modeConfig = _createModeConfig(FIELD_RECIPIENT, mode);
        uint256 chainId = (mode == MODE_CHECK_CATCHALL) ? 0 : targetChainId;
        bytes memory initData = abi.encodePacked(modeConfig, uint8(1), chainId, recipient);
        permit2ClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    /// @notice Initialize policy with recipient subpolicy
    function _initializePolicyWithRecipientSubpolicy(address subpolicyAddr) internal {
        uint32 modeConfig = _createModeConfig(FIELD_RECIPIENT, MODE_CHECK_SUBPOLICY);
        bytes memory initData = abi.encodePacked(
            modeConfig, uint8(1), uint8(FIELD_RECIPIENT), subpolicyAddr, uint256(0)
        );
        permit2ClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    /// @notice Initialize policy with recipientIsSponsor check
    function _initializePolicyWithRecipientIsSponsor() internal {
        uint32 modeConfig = _createModeConfig(FIELD_RECIPIENT_IS_SPONSOR, MODE_CHECK_STORAGE);
        bytes memory initData = abi.encodePacked(modeConfig);
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
            modeConfig, uint8(1), targetChainId, uint256(min) | (uint256(max) << 128)
        );
        permit2ClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    /// @notice Initialize policy with fillExpiry subpolicy
    function _initializePolicyWithFillExpirySubpolicy(address subpolicyAddr) internal {
        uint32 modeConfig = _createModeConfig(FIELD_FILL_EXPIRY, MODE_CHECK_SUBPOLICY);
        bytes memory initData = abi.encodePacked(
            modeConfig, uint8(1), uint8(FIELD_FILL_EXPIRY), subpolicyAddr, uint256(0)
        );
        permit2ClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    /// @notice Initialize policy with tokenOut check
    function _initializePolicyWithTokenOut(
        address token,
        uint256 targetChainId,
        uint8 mode
    )
        internal
    {
        uint32 modeConfig = _createModeConfig(FIELD_TOKEN_OUT, mode);
        uint256 chainId = (mode == MODE_CHECK_CATCHALL) ? 0 : targetChainId;
        bytes memory initData = abi.encodePacked(modeConfig, uint8(1), chainId, token);
        permit2ClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    /// @notice Initialize policy with multiple tokens out
    function _initializePolicyWithMultipleTokensOut(
        address token1,
        address token2,
        uint256 targetChainId,
        uint8 mode
    )
        internal
    {
        uint32 modeConfig = _createModeConfig(FIELD_TOKEN_OUT, mode);
        uint256 chainId = (mode == MODE_CHECK_CATCHALL) ? 0 : targetChainId;
        bytes memory initData =
            abi.encodePacked(modeConfig, uint8(2), chainId, token1, chainId, token2);
        permit2ClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    /// @notice Initialize policy with tokenOut subpolicy
    function _initializePolicyWithTokenOutSubpolicy(address subpolicyAddr) internal {
        uint32 modeConfig = _createModeConfig(FIELD_TOKEN_OUT, MODE_CHECK_SUBPOLICY);
        bytes memory initData = abi.encodePacked(
            modeConfig, uint8(1), uint8(FIELD_TOKEN_OUT), subpolicyAddr, uint256(0)
        );
        permit2ClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    /// @notice Initialize policy with originOps check
    function _initializePolicyWithOriginOps(bool required, uint256 chainId) internal {
        uint32 modeConfig = _createModeConfig(FIELD_ORIGIN_OPS, MODE_CHECK_STORAGE);
        bytes memory initData =
            abi.encodePacked(modeConfig, uint8(1), chainId, uint8(required ? 1 : 0));
        permit2ClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    /// @notice Initialize policy with originOps catchall
    function _initializePolicyWithOriginOpsCatchall(bool required) internal {
        uint32 modeConfig = _createModeConfig(FIELD_ORIGIN_OPS, MODE_CHECK_CATCHALL);
        bytes memory initData =
            abi.encodePacked(modeConfig, uint8(1), uint256(0), uint8(required ? 1 : 0));
        permit2ClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    /// @notice Initialize policy with originOps subpolicy
    function _initializePolicyWithOriginOpsSubpolicy(address subpolicyAddr) internal {
        uint32 modeConfig = _createModeConfig(FIELD_ORIGIN_OPS, MODE_CHECK_SUBPOLICY);
        bytes memory initData = abi.encodePacked(
            modeConfig, uint8(1), uint8(FIELD_ORIGIN_OPS), subpolicyAddr, uint256(0)
        );
        permit2ClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    /// @notice Initialize policy with destOps check
    function _initializePolicyWithDestOps(bool required, uint256 targetChainId) internal {
        // Per-chain destOps keys its requirement on the mandate target chain id, which is only bound
        // to the signed mandate when a target check is enabled; recipientIsSponsor is the minimal one.
        uint32 modeConfig = _createModeConfig(FIELD_DEST_OPS, MODE_CHECK_STORAGE)
            | _createModeConfig(FIELD_RECIPIENT_IS_SPONSOR, MODE_CHECK_STORAGE);
        bytes memory initData =
            abi.encodePacked(modeConfig, uint8(1), targetChainId, uint8(required ? 1 : 0));
        permit2ClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    /// @notice Initialize policy with destOps catchall
    function _initializePolicyWithDestOpsCatchall(bool required) internal {
        uint32 modeConfig = _createModeConfig(FIELD_DEST_OPS, MODE_CHECK_CATCHALL);
        bytes memory initData =
            abi.encodePacked(modeConfig, uint8(1), uint256(0), uint8(required ? 1 : 0));
        permit2ClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    /// @notice Initialize policy with destOps subpolicy
    function _initializePolicyWithDestOpsSubpolicy(address subpolicyAddr) internal {
        // Subpolicy destOps forwards the mandate target chain id, which is only bound to the
        // signed mandate when a target check is enabled; recipientIsSponsor is the minimal one.
        uint32 modeConfig = _createModeConfig(FIELD_DEST_OPS, MODE_CHECK_SUBPOLICY)
            | _createModeConfig(FIELD_RECIPIENT_IS_SPONSOR, MODE_CHECK_STORAGE);
        bytes memory initData = abi.encodePacked(
            modeConfig, uint8(1), uint8(FIELD_DEST_OPS), subpolicyAddr, uint256(0)
        );
        permit2ClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    /// @notice Initialize policy with qualification check
    function _initializePolicyWithQualification(
        address arbiter,
        uint256 chainId,
        uint64 offset,
        bytes32 refValue
    )
        internal
    {
        uint32 modeConfig = _createModeConfig(FIELD_QUALIFICATION, MODE_CHECK_STORAGE);
        bytes memory initData = abi.encodePacked(
            modeConfig,
            uint8(1),
            chainId,
            arbiter,
            uint8(0), // useArbiterHash = false
            uint8(0), // rootNodeIndex
            uint8(1), // ruleCount
            uint8(ParamCondition.EQUAL),
            uint64(offset),
            uint8(32), // length
            refValue,
            uint8(1), // packedNodesCount
            uint256(0) // node: type=RULE, ruleIndex=0
        );
        permit2ClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    /// @notice Initialize policy with qualification catchall
    function _initializePolicyWithQualificationCatchall(
        address arbiter,
        uint64 offset,
        bytes32 refValue
    )
        internal
    {
        uint32 modeConfig = _createModeConfig(FIELD_QUALIFICATION, MODE_CHECK_CATCHALL);
        bytes memory initData = abi.encodePacked(
            modeConfig,
            uint8(1),
            uint256(0), // catchall chainId
            arbiter,
            uint8(0),
            uint8(0),
            uint8(1),
            uint8(ParamCondition.EQUAL),
            uint64(offset),
            uint8(32),
            refValue,
            uint8(1),
            uint256(0)
        );
        permit2ClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    /// @notice Initialize policy with qualification subpolicy
    function _initializePolicyWithQualificationSubpolicy(address subpolicyAddr) internal {
        uint32 modeConfig = _createModeConfig(FIELD_QUALIFICATION, MODE_CHECK_SUBPOLICY);
        bytes memory initData = abi.encodePacked(
            modeConfig, uint8(1), uint8(FIELD_QUALIFICATION), subpolicyAddr, uint256(0)
        );
        permit2ClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    /// @notice Initialize policy with multiple fields (arbiter + tokenIn)
    function _initializePolicyWithMultipleFields(address arbiter, address token) internal {
        uint32 modeConfig = _createModeConfig(FIELD_ARBITER, MODE_CHECK_STORAGE)
            | _createModeConfig(FIELD_TOKEN_IN, MODE_CHECK_STORAGE);
        bytes memory initData = abi.encodePacked(
            modeConfig,
            uint8(1),
            arbiter, // arbiter config
            uint8(1),
            block.chainid,
            token // tokenIn config
        );
        permit2ClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    /// @notice Initialize policy with three fields (arbiter + tokenIn + recipient)
    function _initializePolicyWithThreeFields(
        address arbiter,
        address token,
        address recipient,
        uint256 targetChainId
    )
        internal
    {
        uint32 modeConfig = _createModeConfig(FIELD_ARBITER, MODE_CHECK_STORAGE)
            | _createModeConfig(FIELD_TOKEN_IN, MODE_CHECK_STORAGE)
            | _createModeConfig(FIELD_RECIPIENT, MODE_CHECK_STORAGE);
        bytes memory initData = abi.encodePacked(
            modeConfig,
            uint8(1),
            arbiter, // arbiter config
            uint8(1),
            block.chainid,
            token, // tokenIn config
            uint8(1),
            targetChainId,
            recipient // recipient config
        );
        permit2ClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }
}

