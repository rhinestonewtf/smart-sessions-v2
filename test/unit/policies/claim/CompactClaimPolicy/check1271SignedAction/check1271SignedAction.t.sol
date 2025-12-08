// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import {
    CompactClaimPolicy_Unit_Test
} from "@test/unit/policies/claim/CompactClaimPolicy/CompactClaimPolicy.t.sol";

// Libraries
import { EIP712TypeHashLib } from "@compact-utils/types/EIP712TypeHashLib.sol";
import { DomainLib } from "@the-compact/lib/DomainLib.sol";
import { EfficientHashLib } from "@solady/utils/EfficientHashLib.sol";
import { Bytes32ArrayLib } from "@rhinestone/compact-utils/src/common/Bytes32ArrayLib.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import { ParamRules, ParamRule, ANY_ADDRESS } from "@policies/claim/base/types/BaseDataTypes.sol";
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
    FIELD_RECIPIENT_IS_SPONSOR
} from "@policies/claim/base/types/BaseDataTypes.sol";
import { Constants } from "@compact-utils/types/Constants.sol";

contract CompactClaimPolicy_check1271SignedAction_Test is CompactClaimPolicy_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using EfficientHashLib for bytes32[];
    using Bytes32ArrayLib for bytes32[];

    /*//////////////////////////////////////////////////////////////
                                 VARIABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice Test account (sponsor)
    address internal testAccount;

    /// @notice Test config ID
    ConfigId internal testConfigId;

    /// @notice Test domain separator
    bytes32 internal testDomainSeparator =
        0x1234567890123456789012345678901234567890123456789012345678901234;

    /// @notice Sample minGas value
    uint128 internal constant SAMPLE_MIN_GAS = 100_000;

    /*//////////////////////////////////////////////////////////////
                                   SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        super.setUp();

        testAccount = makeAddr("testAccount");
        testConfigId = ConfigId.wrap(bytes32(uint256(1)));
    }

    /*//////////////////////////////////////////////////////////////
                        UNINITIALIZED POLICY
    //////////////////////////////////////////////////////////////*/

    /// @notice Test that uninitialized policy returns true (all fields SKIP)
    function test_check1271SignedAction_uninitialized_shouldReturnTrue() public {
        // Don't initialize - all modes default to SKIP
        bytes memory compactData = _createCompactDataWithArbiter(makeAddr("anyArbiter"));
        bytes32 expectedHash = this.computeExpectedHash(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "Uninitialized policy should return true");
    }

    /*//////////////////////////////////////////////////////////////
                            FIELD_ARBITER
    //////////////////////////////////////////////////////////////*/

    //--------------------------------------------
    // MODE_SKIP
    //--------------------------------------------

    /// @notice Test arbiter SKIP mode returns true for any arbiter
    function test_check1271SignedAction_arbiter_skip_shouldReturnTrue() public {
        bytes memory compactData = _createCompactDataWithArbiter(makeAddr("anyArbiter"));
        bytes32 expectedHash = this.computeExpectedHash(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "SKIP mode should return true for any arbiter");
    }

    //--------------------------------------------
    // MODE_CHECK_STORAGE
    //--------------------------------------------

    /// @notice Test arbiter storage mode - valid arbiter
    function test_check1271SignedAction_arbiter_storage_valid_shouldPass() public {
        address testArbiter = makeAddr("testArbiter");
        _initializePolicyWithArbiter(testArbiter, MODE_CHECK_STORAGE);

        bytes memory compactData = _createCompactDataWithArbiter(testArbiter);
        bytes32 expectedHash = this.computeExpectedHash(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "Valid arbiter should pass");
    }

    /// @notice Test arbiter storage mode - invalid arbiter
    function test_check1271SignedAction_arbiter_storage_invalid_shouldFail() public {
        address expectedArbiter = makeAddr("expectedArbiter");
        address wrongArbiter = makeAddr("wrongArbiter");

        _initializePolicyWithArbiter(expectedArbiter, MODE_CHECK_STORAGE);

        bytes memory compactData = _createCompactDataWithArbiter(wrongArbiter);
        bytes32 expectedHash = this.computeExpectedHash(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertFalse(result, "Invalid arbiter should fail");
    }

    /// @notice Test arbiter storage mode - multiple arbiters whitelisted
    function test_check1271SignedAction_arbiter_storage_multipleWhitelisted_shouldPass() public {
        address arbiter1 = makeAddr("arbiter1");
        address arbiter2 = makeAddr("arbiter2");

        // Initialize with multiple arbiters
        uint32 modeConfig = _createModeConfig(FIELD_ARBITER, MODE_CHECK_STORAGE);
        bytes memory initData = abi.encodePacked(modeConfig, uint8(2), arbiter1, arbiter2);
        compactClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);

        // Use second arbiter
        bytes memory compactData = _createCompactDataWithArbiter(arbiter2);
        bytes32 expectedHash = this.computeExpectedHash(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "Arbiter in whitelist should pass");
    }

    //--------------------------------------------
    // MODE_CHECK_CATCHALL
    //--------------------------------------------

    /// @notice Test arbiter catchall mode - arbiter in catchall whitelist
    function test_check1271SignedAction_arbiter_catchall_valid_shouldPass() public {
        address testArbiter = makeAddr("testArbiter");
        _initializePolicyWithArbiter(testArbiter, MODE_CHECK_CATCHALL);

        bytes memory compactData = _createCompactDataWithArbiter(testArbiter);
        bytes32 expectedHash = this.computeExpectedHash(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "Arbiter in catchall whitelist should pass");
    }

    /// @notice Test arbiter catchall mode - arbiter not in catchall whitelist
    function test_check1271SignedAction_arbiter_catchall_invalid_shouldFail() public {
        address expectedArbiter = makeAddr("expectedArbiter");
        address wrongArbiter = makeAddr("wrongArbiter");

        _initializePolicyWithArbiter(expectedArbiter, MODE_CHECK_CATCHALL);

        bytes memory compactData = _createCompactDataWithArbiter(wrongArbiter);
        bytes32 expectedHash = this.computeExpectedHash(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertFalse(result, "Arbiter not in catchall whitelist should fail");
    }

    //--------------------------------------------
    // MODE_CHECK_SUBPOLICY
    //--------------------------------------------

    /// @notice Test arbiter subpolicy mode - subpolicy approves
    function test_check1271SignedAction_arbiter_subpolicy_approves_shouldPass() public {
        address testArbiter = makeAddr("testArbiter");

        // Configure mock to approve
        mockSubPolicy.setReturnValue(true);
        _initializePolicyWithArbiterSubpolicy(address(mockSubPolicy));

        bytes memory compactData = _createCompactDataWithArbiter(testArbiter);
        bytes32 expectedHash = this.computeExpectedHash(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "Subpolicy approval should pass");
    }

    /// @notice Test arbiter subpolicy mode - subpolicy rejects
    function test_check1271SignedAction_arbiter_subpolicy_rejects_shouldFail() public {
        address testArbiter = makeAddr("testArbiter");

        // Configure mock to reject
        mockSubPolicy.setReturnValue(false);
        _initializePolicyWithArbiterSubpolicy(address(mockSubPolicy));

        bytes memory compactData = _createCompactDataWithArbiter(testArbiter);
        bytes32 expectedHash = this.computeExpectedHash(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertFalse(result, "Subpolicy rejection should fail");
    }

    /*//////////////////////////////////////////////////////////////
                            FIELD_EXPIRY
    //////////////////////////////////////////////////////////////*/

    //--------------------------------------------
    // MODE_SKIP
    //--------------------------------------------

    /// @notice Test expiry SKIP mode returns true for any expiry
    function test_check1271SignedAction_expiry_skip_shouldReturnTrue() public {
        uint256 anyExpiry = block.timestamp + 999_999;
        bytes memory compactData = _createCompactDataWithExpires(anyExpiry);
        bytes32 expectedHash = this.computeExpectedHash(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "SKIP mode should return true for any expiry");
    }

    //--------------------------------------------
    // MODE_CHECK_STORAGE
    //--------------------------------------------

    /// @notice Test expiry storage mode - expiry within bounds
    function test_check1271SignedAction_expiry_storage_withinBounds_shouldPass() public {
        uint128 minExpiry = uint128(block.timestamp + 1000);
        uint128 maxExpiry = uint128(block.timestamp + 10_000);
        uint256 testExpiry = block.timestamp + 5000;

        _initializePolicyWithExpiry(minExpiry, maxExpiry);

        bytes memory compactData = _createCompactDataWithExpires(testExpiry);
        bytes32 expectedHash = this.computeExpectedHash(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "Expiry within bounds should pass");
    }

    /// @notice Test expiry storage mode - expiry equals min exactly
    function test_check1271SignedAction_expiry_storage_equalsMin_shouldPass() public {
        uint128 minExpiry = uint128(block.timestamp + 1000);
        uint128 maxExpiry = uint128(block.timestamp + 10_000);

        _initializePolicyWithExpiry(minExpiry, maxExpiry);

        bytes memory compactData = _createCompactDataWithExpires(minExpiry);
        bytes32 expectedHash = this.computeExpectedHash(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "Expiry equals min should pass");
    }

    /// @notice Test expiry storage mode - expiry equals max exactly
    function test_check1271SignedAction_expiry_storage_equalsMax_shouldPass() public {
        uint128 minExpiry = uint128(block.timestamp + 1000);
        uint128 maxExpiry = uint128(block.timestamp + 10_000);

        _initializePolicyWithExpiry(minExpiry, maxExpiry);

        bytes memory compactData = _createCompactDataWithExpires(maxExpiry);
        bytes32 expectedHash = this.computeExpectedHash(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "Expiry equals max should pass");
    }

    /// @notice Test expiry storage mode - expiry below min
    function test_check1271SignedAction_expiry_storage_belowMin_shouldFail() public {
        uint128 minExpiry = uint128(block.timestamp + 5000);
        uint128 maxExpiry = uint128(block.timestamp + 10_000);
        uint256 testExpiry = block.timestamp + 1000;

        _initializePolicyWithExpiry(minExpiry, maxExpiry);

        bytes memory compactData = _createCompactDataWithExpires(testExpiry);
        bytes32 expectedHash = this.computeExpectedHash(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertFalse(result, "Expiry below min should fail");
    }

    /// @notice Test expiry storage mode - expiry above max
    function test_check1271SignedAction_expiry_storage_aboveMax_shouldFail() public {
        uint128 minExpiry = uint128(block.timestamp + 1000);
        uint128 maxExpiry = uint128(block.timestamp + 5000);
        uint256 testExpiry = block.timestamp + 10_000;

        _initializePolicyWithExpiry(minExpiry, maxExpiry);

        bytes memory compactData = _createCompactDataWithExpires(testExpiry);
        bytes32 expectedHash = this.computeExpectedHash(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertFalse(result, "Expiry above max should fail");
    }

    //--------------------------------------------
    // MODE_CHECK_SUBPOLICY
    //--------------------------------------------

    /// @notice Test expiry subpolicy mode - subpolicy approves
    function test_check1271SignedAction_expiry_subpolicy_approves_shouldPass() public {
        mockSubPolicy.setReturnValue(true);
        _initializePolicyWithExpirySubpolicy(address(mockSubPolicy));

        uint256 testExpiry = block.timestamp + 5000;
        bytes memory compactData = _createCompactDataWithExpires(testExpiry);
        bytes32 expectedHash = this.computeExpectedHash(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "Subpolicy approval should pass");
    }

    /// @notice Test expiry subpolicy mode - subpolicy rejects
    function test_check1271SignedAction_expiry_subpolicy_rejects_shouldFail() public {
        mockSubPolicy.setReturnValue(false);
        _initializePolicyWithExpirySubpolicy(address(mockSubPolicy));

        uint256 testExpiry = block.timestamp + 5000;
        bytes memory compactData = _createCompactDataWithExpires(testExpiry);
        bytes32 expectedHash = this.computeExpectedHash(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertFalse(result, "Subpolicy rejection should fail");
    }

    /*//////////////////////////////////////////////////////////////
                            FIELD_TOKEN_IN
    //////////////////////////////////////////////////////////////*/

    //--------------------------------------------
    // MODE_SKIP
    //--------------------------------------------

    /// @notice Test tokenIn SKIP mode returns true for any tokenIn
    function test_check1271SignedAction_tokenIn_skip_shouldReturnTrue() public {
        bytes memory compactData = _createCompactDataWithArbiter(makeAddr("anyArbiter"));
        bytes32 expectedHash = this.computeExpectedHash(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "SKIP mode should return true for any tokenIn");
    }

    //--------------------------------------------
    // MODE_CHECK_STORAGE
    //--------------------------------------------

    /// @notice Test tokenIn storage mode - token and lockTag whitelisted
    function test_check1271SignedAction_tokenIn_storage_valid_shouldPass() public {
        address testToken = makeAddr("testToken");
        bytes12 testLockTag = bytes12("test_lock");

        _initializePolicyWithTokenIn(testToken, testLockTag, block.chainid, MODE_CHECK_STORAGE);

        bytes memory compactData = _createCompactDataWithTokenIn(testToken, testLockTag, 1000, 0);
        bytes32 expectedHash = this.computeExpectedHashWithTokenIn(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "Valid token+lockTag should pass");
    }

    /// @notice Test tokenIn storage mode - token not whitelisted
    function test_check1271SignedAction_tokenIn_storage_tokenNotWhitelisted_shouldFail() public {
        address allowedToken = makeAddr("allowedToken");
        address wrongToken = makeAddr("wrongToken");
        bytes12 testLockTag = bytes12("test_lock");

        _initializePolicyWithTokenIn(allowedToken, testLockTag, block.chainid, MODE_CHECK_STORAGE);

        bytes memory compactData = _createCompactDataWithTokenIn(wrongToken, testLockTag, 1000, 0);
        bytes32 expectedHash = this.computeExpectedHashWithTokenIn(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertFalse(result, "Token not whitelisted should fail");
    }

    /// @notice Test tokenIn storage mode - token whitelisted but lockTag differs
    function test_check1271SignedAction_tokenIn_storage_wrongLockTag_shouldFail() public {
        address testToken = makeAddr("testToken");
        bytes12 allowedLockTag = bytes12("allowed_tag");
        bytes12 wrongLockTag = bytes12("wrong_tag");

        _initializePolicyWithTokenIn(testToken, allowedLockTag, block.chainid, MODE_CHECK_STORAGE);

        bytes memory compactData = _createCompactDataWithTokenIn(testToken, wrongLockTag, 1000, 0);
        bytes32 expectedHash = this.computeExpectedHashWithTokenIn(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertFalse(result, "Wrong lockTag should fail");
    }

    /// @notice Test tokenIn storage mode - multiple tokens whitelisted
    function test_check1271SignedAction_tokenIn_storage_multipleWhitelisted_shouldPass() public {
        address token1 = makeAddr("token1");
        address token2 = makeAddr("token2");
        bytes12 lockTag1 = bytes12("lock1");
        bytes12 lockTag2 = bytes12("lock2");

        // Initialize with multiple tokens
        uint32 modeConfig = _createModeConfig(FIELD_TOKEN_IN, MODE_CHECK_STORAGE);
        bytes32 id1 = _packTokenId(token1, lockTag1);
        bytes32 id2 = _packTokenId(token2, lockTag2);
        bytes memory initData = abi.encodePacked(
            modeConfig,
            uint8(2), // count
            block.chainid,
            id1,
            block.chainid,
            id2
        );
        compactClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);

        // Use second token
        bytes memory compactData = _createCompactDataWithTokenIn(token2, lockTag2, 1000, 0);
        bytes32 expectedHash = this.computeExpectedHashWithTokenIn(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "Token in whitelist should pass");
    }

    //--------------------------------------------
    // MODE_CHECK_CATCHALL
    //--------------------------------------------

    /// @notice Test tokenIn catchall mode - token in catchall whitelist
    function test_check1271SignedAction_tokenIn_catchall_valid_shouldPass() public {
        address testToken = makeAddr("testToken");
        bytes12 testLockTag = bytes12("test_lock");

        // Initialize with catchall (chainId 0)
        _initializePolicyWithTokenIn(testToken, testLockTag, 0, MODE_CHECK_CATCHALL);

        bytes memory compactData = _createCompactDataWithTokenIn(testToken, testLockTag, 1000, 0);
        bytes32 expectedHash = this.computeExpectedHashWithTokenIn(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "Token in catchall whitelist should pass");
    }

    /// @notice Test tokenIn catchall mode - token not in catchall whitelist
    function test_check1271SignedAction_tokenIn_catchall_invalid_shouldFail() public {
        address allowedToken = makeAddr("allowedToken");
        address wrongToken = makeAddr("wrongToken");
        bytes12 testLockTag = bytes12("test_lock");

        // Initialize with catchall (chainId 0)
        _initializePolicyWithTokenIn(allowedToken, testLockTag, 0, MODE_CHECK_CATCHALL);

        bytes memory compactData = _createCompactDataWithTokenIn(wrongToken, testLockTag, 1000, 0);
        bytes32 expectedHash = this.computeExpectedHashWithTokenIn(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertFalse(result, "Token not in catchall whitelist should fail");
    }

    //--------------------------------------------
    // MODE_CHECK_SUBPOLICY
    //--------------------------------------------

    /// @notice Test tokenIn subpolicy mode - subpolicy approves
    function test_check1271SignedAction_tokenIn_subpolicy_approves_shouldPass() public {
        address testToken = makeAddr("testToken");
        bytes12 testLockTag = bytes12("test_lock");

        mockSubPolicy.setReturnValue(true);
        _initializePolicyWithTokenInSubpolicy(address(mockSubPolicy));

        bytes memory compactData = _createCompactDataWithTokenIn(testToken, testLockTag, 1000, 0);
        bytes32 expectedHash = this.computeExpectedHashWithTokenIn(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "Subpolicy approval should pass");
    }

    /// @notice Test tokenIn subpolicy mode - subpolicy rejects
    function test_check1271SignedAction_tokenIn_subpolicy_rejects_shouldFail() public {
        address testToken = makeAddr("testToken");
        bytes12 testLockTag = bytes12("test_lock");

        mockSubPolicy.setReturnValue(false);
        _initializePolicyWithTokenInSubpolicy(address(mockSubPolicy));

        bytes memory compactData = _createCompactDataWithTokenIn(testToken, testLockTag, 1000, 0);
        bytes32 expectedHash = this.computeExpectedHashWithTokenIn(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertFalse(result, "Subpolicy rejection should fail");
    }

    /*//////////////////////////////////////////////////////////////
                            FIELD_RECIPIENT
    //////////////////////////////////////////////////////////////*/

    //--------------------------------------------
    // MODE_SKIP
    //--------------------------------------------

    /// @notice Test recipient SKIP mode returns true for any recipient
    function test_check1271SignedAction_recipient_skip_shouldReturnTrue() public {
        bytes memory compactData = _createCompactDataWithArbiter(makeAddr("anyArbiter"));
        bytes32 expectedHash = this.computeExpectedHash(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "SKIP mode should return true for any recipient");
    }

    //--------------------------------------------
    // MODE_CHECK_STORAGE
    //--------------------------------------------

    /// @notice Test recipient storage mode - valid recipient
    function test_check1271SignedAction_recipient_storage_valid_shouldPass() public {
        address testRecipient = makeAddr("testRecipient");
        uint256 targetChainId = 137;

        _initializePolicyWithRecipient(testRecipient, targetChainId, MODE_CHECK_STORAGE);

        bytes memory compactData = _createCompactDataWithRecipient(testRecipient, targetChainId);
        bytes32 expectedHash = this.computeExpectedHashWithTarget(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "Valid recipient should pass");
    }

    /// @notice Test recipient storage mode - invalid recipient
    function test_check1271SignedAction_recipient_storage_invalid_shouldFail() public {
        address allowedRecipient = makeAddr("allowedRecipient");
        address wrongRecipient = makeAddr("wrongRecipient");
        uint256 targetChainId = 137;

        _initializePolicyWithRecipient(allowedRecipient, targetChainId, MODE_CHECK_STORAGE);

        bytes memory compactData = _createCompactDataWithRecipient(wrongRecipient, targetChainId);
        bytes32 expectedHash = this.computeExpectedHashWithTarget(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertFalse(result, "Invalid recipient should fail");
    }

    /// @notice Test recipient storage mode - ANY_ADDRESS allows any recipient
    function test_check1271SignedAction_recipient_storage_anyAddress_shouldPass() public {
        uint256 targetChainId = 137;

        // Initialize with ANY_ADDRESS
        _initializePolicyWithRecipient(ANY_ADDRESS, targetChainId, MODE_CHECK_STORAGE);

        address anyRecipient = makeAddr("anyRecipient");
        bytes memory compactData = _createCompactDataWithRecipient(anyRecipient, targetChainId);
        bytes32 expectedHash = this.computeExpectedHashWithTarget(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "ANY_ADDRESS should allow any recipient");
    }

    //--------------------------------------------
    // MODE_CHECK_CATCHALL
    //--------------------------------------------

    /// @notice Test recipient catchall mode - valid
    function test_check1271SignedAction_recipient_catchall_valid_shouldPass() public {
        address testRecipient = makeAddr("testRecipient");
        uint256 targetChainId = 137;

        // Initialize with catchall (chainId 0)
        _initializePolicyWithRecipient(testRecipient, 0, MODE_CHECK_CATCHALL);

        bytes memory compactData = _createCompactDataWithRecipient(testRecipient, targetChainId);
        bytes32 expectedHash = this.computeExpectedHashWithTarget(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "Recipient in catchall config should pass");
    }

    /// @notice Test recipient catchall mode - invalid
    function test_check1271SignedAction_recipient_catchall_invalid_shouldFail() public {
        address allowedRecipient = makeAddr("allowedRecipient");
        address wrongRecipient = makeAddr("wrongRecipient");
        uint256 targetChainId = 137;

        // Initialize with catchall (chainId 0)
        _initializePolicyWithRecipient(allowedRecipient, 0, MODE_CHECK_CATCHALL);

        bytes memory compactData = _createCompactDataWithRecipient(wrongRecipient, targetChainId);
        bytes32 expectedHash = this.computeExpectedHashWithTarget(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertFalse(result, "Recipient not in catchall config should fail");
    }

    //--------------------------------------------
    // MODE_CHECK_SUBPOLICY
    //--------------------------------------------

    /// @notice Test recipient subpolicy mode - subpolicy approves
    function test_check1271SignedAction_recipient_subpolicy_approves_shouldPass() public {
        address testRecipient = makeAddr("testRecipient");
        uint256 targetChainId = 137;

        mockSubPolicy.setReturnValue(true);
        _initializePolicyWithRecipientSubpolicy(address(mockSubPolicy));

        bytes memory compactData = _createCompactDataWithRecipient(testRecipient, targetChainId);
        bytes32 expectedHash = this.computeExpectedHashWithTarget(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "Subpolicy approval should pass");
    }

    /// @notice Test recipient subpolicy mode - subpolicy rejects
    function test_check1271SignedAction_recipient_subpolicy_rejects_shouldFail() public {
        address testRecipient = makeAddr("testRecipient");
        uint256 targetChainId = 137;

        mockSubPolicy.setReturnValue(false);
        _initializePolicyWithRecipientSubpolicy(address(mockSubPolicy));

        bytes memory compactData = _createCompactDataWithRecipient(testRecipient, targetChainId);
        bytes32 expectedHash = this.computeExpectedHashWithTarget(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertFalse(result, "Subpolicy rejection should fail");
    }

    /*//////////////////////////////////////////////////////////////
                       FIELD_RECIPIENT_IS_SPONSOR
    //////////////////////////////////////////////////////////////*/

    //--------------------------------------------
    // MODE_SKIP
    //--------------------------------------------

    /// @notice Test recipientIsSponsor SKIP mode - allows any recipient
    function test_check1271SignedAction_recipientIsSponsor_skip_shouldPass() public {
        bytes memory compactData = _createCompactDataWithArbiter(makeAddr("anyArbiter"));
        bytes32 expectedHash = this.computeExpectedHash(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "SKIP mode should allow any recipient");
    }

    //--------------------------------------------
    // MODE_CHECK_STORAGE (enabled)
    //--------------------------------------------

    /// @notice Test recipientIsSponsor enabled - recipient equals sponsor
    function test_check1271SignedAction_recipientIsSponsor_enabled_valid_shouldPass() public {
        uint256 targetChainId = 137;

        _initializePolicyWithRecipientIsSponsor();

        // Use testAccount (sponsor) as recipient
        bytes memory compactData = _createCompactDataWithRecipient(testAccount, targetChainId);
        bytes32 expectedHash = this.computeExpectedHashWithTarget(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "Recipient == sponsor should pass");
    }

    /// @notice Test recipientIsSponsor enabled - recipient not equal sponsor
    function test_check1271SignedAction_recipientIsSponsor_enabled_invalid_shouldFail() public {
        address wrongRecipient = makeAddr("wrongRecipient");
        uint256 targetChainId = 137;

        _initializePolicyWithRecipientIsSponsor();

        bytes memory compactData = _createCompactDataWithRecipient(wrongRecipient, targetChainId);
        bytes32 expectedHash = this.computeExpectedHashWithTarget(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertFalse(result, "Recipient != sponsor should fail");
    }

    /*//////////////////////////////////////////////////////////////
                           FIELD_FILL_EXPIRY
    //////////////////////////////////////////////////////////////*/

    //--------------------------------------------
    // MODE_SKIP
    //--------------------------------------------

    /// @notice Test fillExpiry SKIP mode returns true for any fillExpiry
    function test_check1271SignedAction_fillExpiry_skip_shouldReturnTrue() public {
        bytes memory compactData = _createCompactDataWithArbiter(makeAddr("anyArbiter"));
        bytes32 expectedHash = this.computeExpectedHash(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "SKIP mode should return true for any fillExpiry");
    }

    //--------------------------------------------
    // MODE_CHECK_STORAGE
    //--------------------------------------------

    /// @notice Test fillExpiry storage mode - within bounds
    function test_check1271SignedAction_fillExpiry_storage_withinBounds_shouldPass() public {
        uint128 minExpiry = uint128(block.timestamp + 1000);
        uint128 maxExpiry = uint128(block.timestamp + 10_000);
        uint256 testExpiry = block.timestamp + 5000;
        uint256 targetChainId = 137;

        _initializePolicyWithFillExpiry(minExpiry, maxExpiry, targetChainId);

        bytes memory compactData = _createCompactDataWithFillExpiry(testExpiry, targetChainId);
        bytes32 expectedHash = this.computeExpectedHashWithTarget(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "FillExpiry within bounds should pass");
    }

    /// @notice Test fillExpiry storage mode - equals min
    function test_check1271SignedAction_fillExpiry_storage_equalsMin_shouldPass() public {
        uint128 minExpiry = uint128(block.timestamp + 1000);
        uint128 maxExpiry = uint128(block.timestamp + 10_000);
        uint256 targetChainId = 137;

        _initializePolicyWithFillExpiry(minExpiry, maxExpiry, targetChainId);

        bytes memory compactData = _createCompactDataWithFillExpiry(minExpiry, targetChainId);
        bytes32 expectedHash = this.computeExpectedHashWithTarget(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "FillExpiry equals min should pass");
    }

    /// @notice Test fillExpiry storage mode - equals max
    function test_check1271SignedAction_fillExpiry_storage_equalsMax_shouldPass() public {
        uint128 minExpiry = uint128(block.timestamp + 1000);
        uint128 maxExpiry = uint128(block.timestamp + 10_000);
        uint256 targetChainId = 137;

        _initializePolicyWithFillExpiry(minExpiry, maxExpiry, targetChainId);

        bytes memory compactData = _createCompactDataWithFillExpiry(maxExpiry, targetChainId);
        bytes32 expectedHash = this.computeExpectedHashWithTarget(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "FillExpiry equals max should pass");
    }

    /// @notice Test fillExpiry storage mode - below min
    function test_check1271SignedAction_fillExpiry_storage_belowMin_shouldFail() public {
        uint128 minExpiry = uint128(block.timestamp + 5000);
        uint128 maxExpiry = uint128(block.timestamp + 10_000);
        uint256 testExpiry = block.timestamp + 1000;
        uint256 targetChainId = 137;

        _initializePolicyWithFillExpiry(minExpiry, maxExpiry, targetChainId);

        bytes memory compactData = _createCompactDataWithFillExpiry(testExpiry, targetChainId);
        bytes32 expectedHash = this.computeExpectedHashWithTarget(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertFalse(result, "FillExpiry below min should fail");
    }

    /// @notice Test fillExpiry storage mode - above max
    function test_check1271SignedAction_fillExpiry_storage_aboveMax_shouldFail() public {
        uint128 minExpiry = uint128(block.timestamp + 1000);
        uint128 maxExpiry = uint128(block.timestamp + 5000);
        uint256 testExpiry = block.timestamp + 10_000;
        uint256 targetChainId = 137;

        _initializePolicyWithFillExpiry(minExpiry, maxExpiry, targetChainId);

        bytes memory compactData = _createCompactDataWithFillExpiry(testExpiry, targetChainId);
        bytes32 expectedHash = this.computeExpectedHashWithTarget(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertFalse(result, "FillExpiry above max should fail");
    }

    //--------------------------------------------
    // MODE_CHECK_SUBPOLICY
    //--------------------------------------------

    /// @notice Test fillExpiry subpolicy mode - subpolicy approves
    function test_check1271SignedAction_fillExpiry_subpolicy_approves_shouldPass() public {
        uint256 targetChainId = 137;

        mockSubPolicy.setReturnValue(true);
        _initializePolicyWithFillExpirySubpolicy(address(mockSubPolicy));

        uint256 testExpiry = block.timestamp + 5000;
        bytes memory compactData = _createCompactDataWithFillExpiry(testExpiry, targetChainId);
        bytes32 expectedHash = this.computeExpectedHashWithTarget(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "Subpolicy approval should pass");
    }

    /// @notice Test fillExpiry subpolicy mode - subpolicy rejects
    function test_check1271SignedAction_fillExpiry_subpolicy_rejects_shouldFail() public {
        uint256 targetChainId = 137;

        mockSubPolicy.setReturnValue(false);
        _initializePolicyWithFillExpirySubpolicy(address(mockSubPolicy));

        uint256 testExpiry = block.timestamp + 5000;
        bytes memory compactData = _createCompactDataWithFillExpiry(testExpiry, targetChainId);
        bytes32 expectedHash = this.computeExpectedHashWithTarget(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertFalse(result, "Subpolicy rejection should fail");
    }

    /*//////////////////////////////////////////////////////////////
                           FIELD_TOKEN_OUT
    //////////////////////////////////////////////////////////////*/

    //--------------------------------------------
    // MODE_SKIP
    //--------------------------------------------

    /// @notice Test tokenOut SKIP mode returns true for any tokenOut
    function test_check1271SignedAction_tokenOut_skip_shouldReturnTrue() public {
        bytes memory compactData = _createCompactDataWithArbiter(makeAddr("anyArbiter"));
        bytes32 expectedHash = this.computeExpectedHash(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "SKIP mode should return true for any tokenOut");
    }

    //--------------------------------------------
    // MODE_CHECK_STORAGE
    //--------------------------------------------

    /// @notice Test tokenOut storage mode - valid token
    function test_check1271SignedAction_tokenOut_storage_valid_shouldPass() public {
        address testToken = makeAddr("testToken");
        uint256 targetChainId = 137;

        _initializePolicyWithTokenOut(testToken, targetChainId, MODE_CHECK_STORAGE);

        bytes memory compactData = _createCompactDataWithTokenOut(testToken, 1000, targetChainId);
        bytes32 expectedHash = this.computeExpectedHashWithTokenOut(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "Valid tokenOut should pass");
    }

    /// @notice Test tokenOut storage mode - invalid token
    function test_check1271SignedAction_tokenOut_storage_invalid_shouldFail() public {
        address expectedToken = makeAddr("expectedToken");
        address wrongToken = makeAddr("wrongToken");
        uint256 targetChainId = 137;

        _initializePolicyWithTokenOut(expectedToken, targetChainId, MODE_CHECK_STORAGE);

        bytes memory compactData = _createCompactDataWithTokenOut(wrongToken, 1000, targetChainId);
        bytes32 expectedHash = this.computeExpectedHashWithTokenOut(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertFalse(result, "Invalid tokenOut should fail");
    }

    /// @notice Test tokenOut storage mode - multiple tokens whitelisted
    function test_check1271SignedAction_tokenOut_storage_multipleWhitelisted_shouldPass() public {
        address token1 = makeAddr("token1");
        address token2 = makeAddr("token2");
        uint256 targetChainId = 137;

        // Initialize with multiple tokens
        uint32 modeConfig = _createModeConfig(FIELD_TOKEN_OUT, MODE_CHECK_STORAGE);
        bytes memory initData =
            abi.encodePacked(modeConfig, uint8(2), targetChainId, token1, targetChainId, token2);
        compactClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);

        // Use second token
        bytes memory compactData = _createCompactDataWithTokenOut(token2, 1000, targetChainId);
        bytes32 expectedHash = this.computeExpectedHashWithTokenOut(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "Token in whitelist should pass");
    }

    //--------------------------------------------
    // MODE_CHECK_CATCHALL
    //--------------------------------------------

    /// @notice Test tokenOut catchall mode - valid
    function test_check1271SignedAction_tokenOut_catchall_valid_shouldPass() public {
        address testToken = makeAddr("testToken");
        uint256 targetChainId = 137;

        // Initialize with catchall (chainId 0)
        _initializePolicyWithTokenOut(testToken, 0, MODE_CHECK_CATCHALL);

        bytes memory compactData = _createCompactDataWithTokenOut(testToken, 1000, targetChainId);
        bytes32 expectedHash = this.computeExpectedHashWithTokenOut(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "Token in catchall whitelist should pass");
    }

    /// @notice Test tokenOut catchall mode - invalid
    function test_check1271SignedAction_tokenOut_catchall_invalid_shouldFail() public {
        address expectedToken = makeAddr("expectedToken");
        address wrongToken = makeAddr("wrongToken");
        uint256 targetChainId = 137;

        // Initialize with catchall (chainId 0)
        _initializePolicyWithTokenOut(expectedToken, 0, MODE_CHECK_CATCHALL);

        bytes memory compactData = _createCompactDataWithTokenOut(wrongToken, 1000, targetChainId);
        bytes32 expectedHash = this.computeExpectedHashWithTokenOut(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertFalse(result, "Token not in catchall whitelist should fail");
    }

    //--------------------------------------------
    // MODE_CHECK_SUBPOLICY
    //--------------------------------------------

    /// @notice Test tokenOut subpolicy mode - subpolicy approves
    function test_check1271SignedAction_tokenOut_subpolicy_approves_shouldPass() public {
        address testToken = makeAddr("testToken");
        uint256 targetChainId = 137;

        mockSubPolicy.setReturnValue(true);
        _initializePolicyWithTokenOutSubpolicy(address(mockSubPolicy));

        bytes memory compactData = _createCompactDataWithTokenOut(testToken, 1000, targetChainId);
        bytes32 expectedHash = this.computeExpectedHashWithTokenOut(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "Subpolicy approval should pass");
    }

    /// @notice Test tokenOut subpolicy mode - subpolicy rejects
    function test_check1271SignedAction_tokenOut_subpolicy_rejects_shouldFail() public {
        address testToken = makeAddr("testToken");
        uint256 targetChainId = 137;

        mockSubPolicy.setReturnValue(false);
        _initializePolicyWithTokenOutSubpolicy(address(mockSubPolicy));

        bytes memory compactData = _createCompactDataWithTokenOut(testToken, 1000, targetChainId);
        bytes32 expectedHash = this.computeExpectedHashWithTokenOut(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertFalse(result, "Subpolicy rejection should fail");
    }

    /*//////////////////////////////////////////////////////////////
                          FIELD_ORIGIN_OPS
    //////////////////////////////////////////////////////////////*/

    //--------------------------------------------
    // MODE_SKIP
    //--------------------------------------------

    /// @notice Test originOps SKIP mode returns true for any ops
    function test_check1271SignedAction_originOps_skip_shouldReturnTrue() public {
        bytes memory compactData = _createCompactDataWithArbiter(makeAddr("anyArbiter"));
        bytes32 expectedHash = this.computeExpectedHash(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "SKIP mode should return true for any originOps");
    }

    //--------------------------------------------
    // MODE_CHECK_STORAGE
    //--------------------------------------------

    /// @notice Test originOps storage mode - required and present
    function test_check1271SignedAction_originOps_storage_requiredAndPresent_shouldPass() public {
        _initializePolicyWithOriginOps(true, block.chainid, MODE_CHECK_STORAGE);

        bytes32 nonEmptyOpsHash = keccak256("some ops");
        bytes memory compactData = _createCompactDataWithOriginOps(nonEmptyOpsHash, 0);
        bytes32 expectedHash = this.computeExpectedHashWithMandateExpanded(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "Required originOps present should pass");
    }

    /// @notice Test originOps storage mode - required but missing
    function test_check1271SignedAction_originOps_storage_requiredButMissing_shouldFail() public {
        _initializePolicyWithOriginOps(true, block.chainid, MODE_CHECK_STORAGE);

        bytes memory compactData = _createCompactDataWithOriginOps(Constants.NO_OPS, 0);
        bytes32 expectedHash = this.computeExpectedHashWithMandateExpanded(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertFalse(result, "Required originOps missing should fail");
    }

    /// @notice Test originOps storage mode - not required and missing
    function test_check1271SignedAction_originOps_storage_notRequiredAndMissing_shouldPass()
        public
    {
        _initializePolicyWithOriginOps(false, block.chainid, MODE_CHECK_STORAGE);

        bytes memory compactData = _createCompactDataWithOriginOps(Constants.NO_OPS, 0);
        bytes32 expectedHash = this.computeExpectedHashWithMandateExpanded(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "Not required originOps missing should pass");
    }

    /// @notice Test originOps storage mode - not required but present
    function test_check1271SignedAction_originOps_storage_notRequiredButPresent_shouldFail()
        public
    {
        _initializePolicyWithOriginOps(false, block.chainid, MODE_CHECK_STORAGE);

        bytes32 nonEmptyOpsHash = keccak256("some ops");
        bytes memory compactData = _createCompactDataWithOriginOps(nonEmptyOpsHash, 0);
        bytes32 expectedHash = this.computeExpectedHashWithMandateExpanded(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertFalse(result, "Not required originOps present should fail");
    }

    //--------------------------------------------
    // MODE_CHECK_CATCHALL
    //--------------------------------------------

    /// @notice Test originOps catchall mode - config satisfied
    function test_check1271SignedAction_originOps_catchall_satisfied_shouldPass() public {
        // Initialize with catchall (chainId 0), required=true
        _initializePolicyWithOriginOps(true, 0, MODE_CHECK_CATCHALL);

        bytes32 nonEmptyOpsHash = keccak256("some ops");
        bytes memory compactData = _createCompactDataWithOriginOps(nonEmptyOpsHash, 0);
        bytes32 expectedHash = this.computeExpectedHashWithMandateExpanded(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "Catchall config satisfied should pass");
    }

    /// @notice Test originOps catchall mode - config not satisfied
    function test_check1271SignedAction_originOps_catchall_notSatisfied_shouldFail() public {
        // Initialize with catchall (chainId 0), required=true
        _initializePolicyWithOriginOps(true, 0, MODE_CHECK_CATCHALL);

        bytes memory compactData = _createCompactDataWithOriginOps(Constants.NO_OPS, 0);
        bytes32 expectedHash = this.computeExpectedHashWithMandateExpanded(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertFalse(result, "Catchall config not satisfied should fail");
    }

    //--------------------------------------------
    // MODE_CHECK_SUBPOLICY
    //--------------------------------------------

    /// @notice Test originOps subpolicy mode - subpolicy approves
    function test_check1271SignedAction_originOps_subpolicy_approves_shouldPass() public {
        mockSubPolicy.setReturnValue(true);
        _initializePolicyWithOriginOpsSubpolicy(address(mockSubPolicy));

        bytes32 nonEmptyOpsHash = keccak256("some ops");
        bytes memory compactData = _createCompactDataWithOriginOps(nonEmptyOpsHash, 0);
        bytes32 expectedHash = this.computeExpectedHashWithMandateExpanded(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "Subpolicy approval should pass");
    }

    /// @notice Test originOps subpolicy mode - subpolicy rejects
    function test_check1271SignedAction_originOps_subpolicy_rejects_shouldFail() public {
        mockSubPolicy.setReturnValue(false);
        _initializePolicyWithOriginOpsSubpolicy(address(mockSubPolicy));

        bytes32 nonEmptyOpsHash = keccak256("some ops");
        bytes memory compactData = _createCompactDataWithOriginOps(nonEmptyOpsHash, 0);
        bytes32 expectedHash = this.computeExpectedHashWithMandateExpanded(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertFalse(result, "Subpolicy rejection should fail");
    }

    /*//////////////////////////////////////////////////////////////
                            FIELD_DEST_OPS
    //////////////////////////////////////////////////////////////*/

    //--------------------------------------------
    // MODE_SKIP
    //--------------------------------------------

    /// @notice Test destOps SKIP mode returns true for any ops
    function test_check1271SignedAction_destOps_skip_shouldReturnTrue() public {
        // Use basic compact data - destOps is in mandate which gets hashed
        bytes memory compactData = _createCompactDataWithArbiter(makeAddr("anyArbiter"));
        bytes32 expectedHash = this.computeExpectedHash(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "SKIP mode should return true for any destOps");
    }

    //--------------------------------------------
    // MODE_CHECK_STORAGE
    //--------------------------------------------

    /// @notice Test destOps storage mode - required and present
    function test_check1271SignedAction_destOps_storage_requiredAndPresent_shouldPass() public {
        uint256 targetChainId = 137;
        _initializePolicyWithDestOps(true, targetChainId, MODE_CHECK_STORAGE);

        bytes32 nonEmptyOpsHash = keccak256("some ops");
        bytes memory compactData = _createCompactDataWithDestOps(nonEmptyOpsHash, targetChainId);
        bytes32 expectedHash = this.computeExpectedHashWithMandateExpanded(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "Required destOps present should pass");
    }

    /// @notice Test destOps storage mode - required but missing
    function test_check1271SignedAction_destOps_storage_requiredButMissing_shouldFail() public {
        uint256 targetChainId = 137;
        _initializePolicyWithDestOps(true, targetChainId, MODE_CHECK_STORAGE);

        bytes memory compactData = _createCompactDataWithDestOps(Constants.NO_OPS, targetChainId);
        bytes32 expectedHash = this.computeExpectedHashWithMandateExpanded(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertFalse(result, "Required destOps missing should fail");
    }

    /// @notice Test destOps storage mode - not required and missing
    function test_check1271SignedAction_destOps_storage_notRequiredAndMissing_shouldPass() public {
        uint256 targetChainId = 137;
        _initializePolicyWithDestOps(false, targetChainId, MODE_CHECK_STORAGE);

        bytes memory compactData = _createCompactDataWithDestOps(Constants.NO_OPS, targetChainId);
        bytes32 expectedHash = this.computeExpectedHashWithMandateExpanded(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "Not required destOps missing should pass");
    }

    /// @notice Test destOps storage mode - not required but present
    function test_check1271SignedAction_destOps_storage_notRequiredButPresent_shouldFail() public {
        uint256 targetChainId = 137;
        _initializePolicyWithDestOps(false, targetChainId, MODE_CHECK_STORAGE);

        bytes32 nonEmptyOpsHash = keccak256("some ops");
        bytes memory compactData = _createCompactDataWithDestOps(nonEmptyOpsHash, targetChainId);
        bytes32 expectedHash = this.computeExpectedHashWithMandateExpanded(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertFalse(result, "Not required destOps present should fail");
    }

    //--------------------------------------------
    // MODE_CHECK_CATCHALL
    //--------------------------------------------

    /// @notice Test destOps catchall mode - config satisfied
    function test_check1271SignedAction_destOps_catchall_satisfied_shouldPass() public {
        _initializePolicyWithDestOps(true, 0, MODE_CHECK_CATCHALL);

        uint256 targetChainId = 137;
        bytes32 nonEmptyOpsHash = keccak256("some ops");
        bytes memory compactData = _createCompactDataWithDestOps(nonEmptyOpsHash, targetChainId);
        bytes32 expectedHash = this.computeExpectedHashWithMandateExpanded(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "Catchall config satisfied should pass");
    }

    /// @notice Test destOps catchall mode - config not satisfied
    function test_check1271SignedAction_destOps_catchall_notSatisfied_shouldFail() public {
        _initializePolicyWithDestOps(true, 0, MODE_CHECK_CATCHALL);

        uint256 targetChainId = 137;
        bytes memory compactData = _createCompactDataWithDestOps(Constants.NO_OPS, targetChainId);
        bytes32 expectedHash = this.computeExpectedHashWithMandateExpanded(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertFalse(result, "Catchall config not satisfied should fail");
    }

    //--------------------------------------------
    // MODE_CHECK_SUBPOLICY
    //--------------------------------------------

    /// @notice Test destOps subpolicy mode - subpolicy approves
    function test_check1271SignedAction_destOps_subpolicy_approves_shouldPass() public {
        mockSubPolicy.setReturnValue(true);
        _initializePolicyWithDestOpsSubpolicy(address(mockSubPolicy));

        uint256 targetChainId = 137;
        bytes32 nonEmptyOpsHash = keccak256("some ops");
        bytes memory compactData = _createCompactDataWithDestOps(nonEmptyOpsHash, targetChainId);
        bytes32 expectedHash = this.computeExpectedHashWithMandateExpanded(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "Subpolicy approval should pass");
    }

    /// @notice Test destOps subpolicy mode - subpolicy rejects
    function test_check1271SignedAction_destOps_subpolicy_rejects_shouldFail() public {
        mockSubPolicy.setReturnValue(false);
        _initializePolicyWithDestOpsSubpolicy(address(mockSubPolicy));

        uint256 targetChainId = 137;
        bytes32 nonEmptyOpsHash = keccak256("some ops");
        bytes memory compactData = _createCompactDataWithDestOps(nonEmptyOpsHash, targetChainId);
        bytes32 expectedHash = this.computeExpectedHashWithMandateExpanded(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertFalse(result, "Subpolicy rejection should fail");
    }

    /*//////////////////////////////////////////////////////////////
                         FIELD_QUALIFICATION
    //////////////////////////////////////////////////////////////*/

    //--------------------------------------------
    // MODE_SKIP
    //--------------------------------------------

    /// @notice Test qualification SKIP mode returns true for any qualification
    function test_check1271SignedAction_qualification_skip_shouldReturnTrue() public {
        bytes memory compactData = _createCompactDataWithArbiter(makeAddr("anyArbiter"));
        bytes32 expectedHash = this.computeExpectedHash(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "SKIP mode should return true for any qualification");
    }

    //--------------------------------------------
    // MODE_CHECK_STORAGE
    //--------------------------------------------

    /// @notice Test qualification storage mode - valid qualification
    function test_check1271SignedAction_qualification_storage_valid_shouldPass() public {
        bytes32 qualData = keccak256("valid qualification");
        _initializePolicyWithQualification(qualData, false, MODE_CHECK_STORAGE);

        bytes memory compactData = _createCompactDataWithQualificationStorage(qualData);
        bytes32 expectedHash = this.computeExpectedHashWithQualificationExpanded(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "Valid qualification should pass");
    }

    /// @notice Test qualification storage mode - invalid qualification
    function test_check1271SignedAction_qualification_storage_invalid_shouldFail() public {
        bytes32 expectedQualHash = keccak256("expected qualification");
        bytes32 wrongHash = keccak256("wrong qualification");
        _initializePolicyWithQualification(expectedQualHash, false, MODE_CHECK_STORAGE);

        bytes memory compactData = _createCompactDataWithQualificationStorage(wrongHash);
        bytes32 expectedHash = this.computeExpectedHashWithMandateExpanded(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertFalse(result, "Invalid qualification should fail");
    }

    //--------------------------------------------
    // MODE_CHECK_CATCHALL
    //--------------------------------------------

    /// @notice Test qualification catchall mode - valid
    function test_check1271SignedAction_qualification_catchall_valid_shouldPass() public {
        bytes32 qualData = keccak256("valid qualification");
        _initializePolicyWithQualification(qualData, false, MODE_CHECK_CATCHALL);

        bytes memory compactData = _createCompactDataWithQualificationStorage(qualData);
        bytes32 expectedHash = this.computeExpectedHashWithQualificationExpanded(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "Catchall rules pass should pass");
    }

    /// @notice Test qualification catchall mode - invalid
    function test_check1271SignedAction_qualification_catchall_invalid_shouldFail() public {
        bytes32 expectedQualHash = keccak256("expected qualification");
        bytes32 wrongHash = keccak256("wrong qualification");
        _initializePolicyWithQualification(expectedQualHash, false, MODE_CHECK_CATCHALL);

        bytes memory compactData = _createCompactDataWithQualificationStorage(wrongHash);
        bytes32 expectedHash = this.computeExpectedHashWithMandateExpanded(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertFalse(result, "Catchall rules fail should fail");
    }

    //--------------------------------------------
    // MODE_CHECK_SUBPOLICY
    //--------------------------------------------

    /// @notice Test qualification subpolicy mode - subpolicy approves
    function test_check1271SignedAction_qualification_subpolicy_approves_shouldPass() public {
        mockSubPolicy.setReturnValue(true);
        _initializePolicyWithQualificationSubpolicy(address(mockSubPolicy));

        bytes32 qualData = keccak256("any qualification");
        bytes memory compactData = _createCompactDataWithQualificationSubpolicy(qualData);
        bytes32 expectedHash = this.computeExpectedHashWithQualificationSubpolicy(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "Subpolicy approval should pass");
    }

    /// @notice Test qualification subpolicy mode - subpolicy rejects
    function test_check1271SignedAction_qualification_subpolicy_rejects_shouldFail() public {
        mockSubPolicy.setReturnValue(false);
        _initializePolicyWithQualificationSubpolicy(address(mockSubPolicy));

        bytes32 qualHash = keccak256("any qualification");
        bytes memory compactData = _createCompactDataWithQualificationSubpolicy(qualHash);
        bytes32 expectedHash = this.computeExpectedHashWithMandateExpanded(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertFalse(result, "Subpolicy rejection should fail");
    }

    /*//////////////////////////////////////////////////////////////
                        MULTIPLE FIELDS ENABLED
    //////////////////////////////////////////////////////////////*/

    /// @notice Test all fields pass - should return true
    function test_check1271SignedAction_multipleFields_allPass_shouldReturnTrue() public {
        address testArbiter = makeAddr("testArbiter");
        address testRecipient = makeAddr("testRecipient");
        address testTokenOut = makeAddr("testTokenOut");
        uint256 targetChainId = 137;

        uint32 modeConfig = _createModeConfig(FIELD_ARBITER, MODE_CHECK_STORAGE)
            | _createModeConfig(FIELD_RECIPIENT, MODE_CHECK_STORAGE)
            | _createModeConfig(FIELD_TOKEN_OUT, MODE_CHECK_STORAGE);

        bytes memory initData = abi.encodePacked(
            modeConfig,
            uint8(1),
            testArbiter,
            uint8(1),
            targetChainId,
            testRecipient,
            uint8(1),
            targetChainId,
            testTokenOut
        );
        compactClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);

        bytes memory compactData = _createCompactDataWithMultipleFields(
            testArbiter, testRecipient, testTokenOut, targetChainId
        );
        bytes32 expectedHash = this.computeExpectedHashWithTokenOut(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "All fields pass should return true");
    }

    /// @notice Test first field fails - should return false
    function test_check1271SignedAction_multipleFields_firstFails_shouldReturnFalse() public {
        address expectedArbiter = makeAddr("expectedArbiter");
        address wrongArbiter = makeAddr("wrongArbiter");
        address testRecipient = makeAddr("testRecipient");
        address testTokenOut = makeAddr("testTokenOut");
        uint256 targetChainId = 137;

        uint32 modeConfig = _createModeConfig(FIELD_ARBITER, MODE_CHECK_STORAGE)
            | _createModeConfig(FIELD_RECIPIENT, MODE_CHECK_STORAGE)
            | _createModeConfig(FIELD_TOKEN_OUT, MODE_CHECK_STORAGE);

        bytes memory initData = abi.encodePacked(
            modeConfig,
            uint8(1),
            expectedArbiter,
            uint8(1),
            targetChainId,
            testRecipient,
            uint8(1),
            targetChainId,
            testTokenOut
        );
        compactClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);

        bytes memory compactData = _createCompactDataWithMultipleFields(
            wrongArbiter, testRecipient, testTokenOut, targetChainId
        );
        bytes32 expectedHash = this.computeExpectedHashWithTokenOut(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertFalse(result, "First field fails should return false");
    }

    /// @notice Test middle field fails - should return false
    function test_check1271SignedAction_multipleFields_middleFails_shouldReturnFalse() public {
        address testArbiter = makeAddr("testArbiter");
        address expectedRecipient = makeAddr("expectedRecipient");
        address wrongRecipient = makeAddr("wrongRecipient");
        address testTokenOut = makeAddr("testTokenOut");
        uint256 targetChainId = 137;

        uint32 modeConfig = _createModeConfig(FIELD_ARBITER, MODE_CHECK_STORAGE)
            | _createModeConfig(FIELD_RECIPIENT, MODE_CHECK_STORAGE)
            | _createModeConfig(FIELD_TOKEN_OUT, MODE_CHECK_STORAGE);

        bytes memory initData = abi.encodePacked(
            modeConfig,
            uint8(1),
            testArbiter,
            uint8(1),
            targetChainId,
            expectedRecipient,
            uint8(1),
            targetChainId,
            testTokenOut
        );
        compactClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);

        bytes memory compactData = _createCompactDataWithMultipleFields(
            testArbiter, wrongRecipient, testTokenOut, targetChainId
        );
        bytes32 expectedHash = this.computeExpectedHashWithTokenOut(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertFalse(result, "Middle field fails should return false");
    }

    /// @notice Test last field fails - should return false
    function test_check1271SignedAction_multipleFields_lastFails_shouldReturnFalse() public {
        address testArbiter = makeAddr("testArbiter");
        address testRecipient = makeAddr("testRecipient");
        address expectedTokenOut = makeAddr("expectedTokenOut");
        address wrongTokenOut = makeAddr("wrongTokenOut");
        uint256 targetChainId = 137;

        uint32 modeConfig = _createModeConfig(FIELD_ARBITER, MODE_CHECK_STORAGE)
            | _createModeConfig(FIELD_RECIPIENT, MODE_CHECK_STORAGE)
            | _createModeConfig(FIELD_TOKEN_OUT, MODE_CHECK_STORAGE);

        bytes memory initData = abi.encodePacked(
            modeConfig,
            uint8(1),
            testArbiter,
            uint8(1),
            targetChainId,
            testRecipient,
            uint8(1),
            targetChainId,
            expectedTokenOut
        );
        compactClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);

        bytes memory compactData = _createCompactDataWithMultipleFields(
            testArbiter, testRecipient, wrongTokenOut, targetChainId
        );
        bytes32 expectedHash = this.computeExpectedHashWithTokenOut(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertFalse(result, "Last field fails should return false");
    }

    /*//////////////////////////////////////////////////////////////
                          HASH VERIFICATION
    //////////////////////////////////////////////////////////////*/

    function test_check1271SignedAction_hash_matches_shouldReturnTrue() public {
        // Initialize with arbiter (need at least one field enabled)
        address testArbiter = makeAddr("testArbiter");
        _initializePolicyWithArbiter(testArbiter, MODE_CHECK_STORAGE);

        bytes memory compactData = _createCompactDataWithArbiter(testArbiter);
        bytes32 expectedHash = this.computeExpectedHash(compactData);

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(expectedHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertTrue(result, "Matching hash should return true");
    }

    function test_check1271SignedAction_hash_mismatch_shouldReturnFalse() public {
        // Initialize with arbiter
        address testArbiter = makeAddr("testArbiter");
        _initializePolicyWithArbiter(testArbiter, MODE_CHECK_STORAGE);

        bytes memory compactData = _createCompactDataWithArbiter(testArbiter);
        bytes32 wrongHash = keccak256("wrong hash");

        bool result = compactClaimPolicy.check1271SignedAction(
            testConfigId,
            admin.addr,
            testAccount,
            DomainLib.withDomain(wrongHash, testDomainSeparator),
            abi.encodePacked(testDomainSeparator, compactData)
        );

        assertFalse(result, "Mismatching hash should return false");
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    //--------------------------------------------
    // ARBITER HELPERS
    //--------------------------------------------

    /// @notice Initialize policy with arbiter check (STORAGE or CATCHALL mode)
    function _initializePolicyWithArbiter(address arbiter, uint8 mode) internal {
        uint32 modeConfig = _createModeConfig(FIELD_ARBITER, mode);
        bytes memory initData = abi.encodePacked(modeConfig, uint8(1), arbiter);
        compactClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    //--------------------------------------------
    // EXPIRY HELPERS
    //--------------------------------------------

    /// @notice Initialize policy with expiry bounds
    function _initializePolicyWithExpiry(uint128 minExpiry, uint128 maxExpiry) internal {
        uint32 modeConfig = _createModeConfig(FIELD_EXPIRY, MODE_CHECK_STORAGE);
        bytes memory initData =
            abi.encodePacked(modeConfig, uint256(minExpiry) | (uint256(maxExpiry) << 128));
        compactClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    //--------------------------------------------
    // TOKEN_IN HELPERS
    //--------------------------------------------

    /// @notice Initialize policy with tokenIn (STORAGE or CATCHALL mode)
    function _initializePolicyWithTokenIn(
        address token,
        bytes12 lockTag,
        uint256 chainId,
        uint8 mode
    )
        internal
    {
        uint32 modeConfig = _createModeConfig(FIELD_TOKEN_IN, mode);
        uint256 compactId = (uint256(uint96(lockTag)) << 160) | uint256(uint160(token));
        bytes memory initData = abi.encodePacked(modeConfig, uint8(1), uint256(chainId), compactId);
        compactClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    //--------------------------------------------
    // RECIPIENT HELPERS
    //--------------------------------------------

    /// @notice Initialize policy with recipient (STORAGE or CATCHALL mode)
    function _initializePolicyWithRecipient(
        address recipient,
        uint256 chainId,
        uint8 mode
    )
        internal
    {
        uint32 modeConfig = _createModeConfig(FIELD_RECIPIENT, mode);
        bytes memory initData = abi.encodePacked(modeConfig, uint8(1), chainId, recipient);
        compactClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    /// @notice Initialize policy with recipientIsSponsor enabled
    function _initializePolicyWithRecipientIsSponsor() internal {
        uint32 modeConfig = _createModeConfig(FIELD_RECIPIENT_IS_SPONSOR, MODE_CHECK_STORAGE);
        bytes memory initData = abi.encodePacked(modeConfig);
        compactClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    //--------------------------------------------
    // FILL_EXPIRY HELPERS
    //--------------------------------------------

    /// @notice Initialize policy with fillExpiry bounds
    function _initializePolicyWithFillExpiry(
        uint128 minExpiry,
        uint128 maxExpiry,
        uint256 chainId
    )
        internal
    {
        uint32 modeConfig = _createModeConfig(FIELD_FILL_EXPIRY, MODE_CHECK_STORAGE);
        bytes memory initData = abi.encodePacked(
            modeConfig, uint8(1), chainId, uint256(minExpiry) | (uint256(maxExpiry) << 128)
        );
        compactClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    //--------------------------------------------
    // TOKEN_OUT HELPERS
    //--------------------------------------------

    /// @notice Initialize policy with tokenOut (STORAGE or CATCHALL mode)
    function _initializePolicyWithTokenOut(address token, uint256 chainId, uint8 mode) internal {
        uint32 modeConfig = _createModeConfig(FIELD_TOKEN_OUT, mode);
        bytes memory initData = abi.encodePacked(modeConfig, uint8(1), chainId, token);
        compactClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    //--------------------------------------------
    // ORIGIN_OPS HELPERS
    //--------------------------------------------

    /// @notice Initialize policy with originOps (STORAGE or CATCHALL mode)
    function _initializePolicyWithOriginOps(bool required, uint256 chainId, uint8 mode) internal {
        uint32 modeConfig = _createModeConfig(FIELD_ORIGIN_OPS, mode);
        bytes memory initData =
            abi.encodePacked(modeConfig, uint8(1), chainId, uint8(required ? 1 : 0));
        compactClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    //--------------------------------------------
    // DEST_OPS HELPERS
    //--------------------------------------------

    /// @notice Initialize policy with destOps (STORAGE or CATCHALL mode)
    function _initializePolicyWithDestOps(bool required, uint256 chainId, uint8 mode) internal {
        uint32 modeConfig = _createModeConfig(FIELD_DEST_OPS, mode);
        bytes memory initData =
            abi.encodePacked(modeConfig, uint8(1), chainId, uint8(required ? 1 : 0));
        compactClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    //--------------------------------------------
    // QUALIFICATION HELPERS
    //--------------------------------------------

    /// @notice Initialize policy with qualification (uses ParamRules)
    function _initializePolicyWithQualification(
        bytes32 qualData,
        bool useArbiterHash,
        uint8 mode
    )
        internal
    {
        uint32 modeConfig = _createModeConfig(FIELD_QUALIFICATION, mode);

        address arbiter = makeAddr("arbiter");

        // For CATCHALL mode, use chainId=0; for STORAGE mode, use actual chainId
        uint256 chainId = (mode == MODE_CHECK_CATCHALL) ? 0 : block.chainid;

        bytes memory qualConfig = abi.encodePacked(
            uint8(1), // count
            uint256(chainId), // chainId (0 for catchall)
            arbiter, // arbiter
            uint8(useArbiterHash ? 1 : 0), // useArbiterHash
            uint8(0), // rootNodeIndex
            uint8(1), // ruleCount
            uint8(ParamCondition.EQUAL), // condition
            uint64(0), // offset
            uint8(32), // length
            qualData, // ref (the data we're checking against)
            uint8(1), // packedNodesCount
            uint256(0) // packedNode[0]
        );

        bytes memory initData = abi.encodePacked(modeConfig, qualConfig);
        compactClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    //--------------------------------------------
    // SUBPOLICY HELPERS
    //--------------------------------------------

    /// @notice Initialize policy with arbiter subpolicy
    function _initializePolicyWithArbiterSubpolicy(address subPolicy) internal {
        uint32 modeConfig = _createModeConfig(FIELD_ARBITER, MODE_CHECK_SUBPOLICY);
        bytes memory initData = abi.encodePacked(
            modeConfig,
            uint8(1), // count (1 byte)
            uint8(FIELD_ARBITER), // fieldId (1 byte)
            subPolicy, // policyAddress (20 bytes)
            uint256(0) // initDataLength (32 bytes)
        );
        compactClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    /// @notice Initialize policy with expiry subpolicy
    function _initializePolicyWithExpirySubpolicy(address subPolicy) internal {
        uint32 modeConfig = _createModeConfig(FIELD_EXPIRY, MODE_CHECK_SUBPOLICY);
        bytes memory initData =
            abi.encodePacked(modeConfig, uint8(1), uint8(FIELD_EXPIRY), subPolicy, uint256(0));
        compactClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    /// @notice Initialize policy with tokenIn subpolicy
    function _initializePolicyWithTokenInSubpolicy(address subPolicy) internal {
        uint32 modeConfig = _createModeConfig(FIELD_TOKEN_IN, MODE_CHECK_SUBPOLICY);
        bytes memory initData =
            abi.encodePacked(modeConfig, uint8(1), uint8(FIELD_TOKEN_IN), subPolicy, uint256(0));
        compactClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    /// @notice Initialize policy with recipient subpolicy
    function _initializePolicyWithRecipientSubpolicy(address subPolicy) internal {
        uint32 modeConfig = _createModeConfig(FIELD_RECIPIENT, MODE_CHECK_SUBPOLICY);
        bytes memory initData =
            abi.encodePacked(modeConfig, uint8(1), uint8(FIELD_RECIPIENT), subPolicy, uint256(0));
        compactClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    /// @notice Initialize policy with fillExpiry subpolicy
    function _initializePolicyWithFillExpirySubpolicy(address subPolicy) internal {
        uint32 modeConfig = _createModeConfig(FIELD_FILL_EXPIRY, MODE_CHECK_SUBPOLICY);
        bytes memory initData = abi.encodePacked(
            modeConfig, uint8(1), uint8(FIELD_FILL_EXPIRY), subPolicy, uint256(0)
        );
        compactClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    /// @notice Initialize policy with tokenOut subpolicy
    function _initializePolicyWithTokenOutSubpolicy(address subPolicy) internal {
        uint32 modeConfig = _createModeConfig(FIELD_TOKEN_OUT, MODE_CHECK_SUBPOLICY);
        bytes memory initData =
            abi.encodePacked(modeConfig, uint8(1), uint8(FIELD_TOKEN_OUT), subPolicy, uint256(0));
        compactClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    /// @notice Initialize policy with originOps subpolicy
    function _initializePolicyWithOriginOpsSubpolicy(address subPolicy) internal {
        uint32 modeConfig = _createModeConfig(FIELD_ORIGIN_OPS, MODE_CHECK_SUBPOLICY);
        bytes memory initData = abi.encodePacked(
            modeConfig, uint8(1), uint8(FIELD_ORIGIN_OPS), subPolicy, uint256(0)
        );
        compactClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    /// @notice Initialize policy with destOps subpolicy
    function _initializePolicyWithDestOpsSubpolicy(address subPolicy) internal {
        uint32 modeConfig = _createModeConfig(FIELD_DEST_OPS, MODE_CHECK_SUBPOLICY);
        bytes memory initData =
            abi.encodePacked(modeConfig, uint8(1), uint8(FIELD_DEST_OPS), subPolicy, uint256(0));
        compactClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    /// @notice Initialize policy with qualification subpolicy
    function _initializePolicyWithQualificationSubpolicy(address subPolicy) internal {
        uint32 modeConfig = _createModeConfig(FIELD_QUALIFICATION, MODE_CHECK_SUBPOLICY);
        bytes memory initData = abi.encodePacked(
            modeConfig, uint8(1), uint8(FIELD_QUALIFICATION), subPolicy, uint256(0)
        );
        compactClaimPolicy.initializeWithMultiplexer(testAccount, testConfigId, initData);
    }

    /*//////////////////////////////////////////////////////////////
                         DATA CREATION HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Create basic compact header
    function _createCompactHeader() private view returns (bytes memory) {
        return abi.encodePacked(
            uint256(1), // nonce
            uint256(block.timestamp + 3600), // expires
            uint256(0) // otherElements length
        );
    }

    /// @notice Create element header
    function _createElementHeader(
        address arbiter,
        uint256 elementIndex
    )
        private
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(arbiter, elementIndex);
    }

    /// @notice Compute basic mandate hash
    function _computeBasicMandateHash() private pure returns (bytes32) {
        return EIP712TypeHashLib.hashMandateRaw(
            keccak256("target"),
            uint128(0),
            Constants.NO_OPS,
            Constants.NO_OPS,
            keccak256("qualification")
        );
    }

    /// @notice Create mandate footer
    function _createMandateFooter() private pure returns (bytes memory) {
        return abi.encodePacked(
            uint128(0), Constants.NO_OPS, Constants.NO_OPS, keccak256("qualification")
        );
    }

    /// @notice Create Compact data with specific arbiter
    function _createCompactDataWithArbiter(address arbiter) internal view returns (bytes memory) {
        bytes memory header = _createCompactHeader();
        bytes memory elementHeader = _createElementHeader(arbiter, 0);
        bytes32 mandateHash = _computeBasicMandateHash();
        return abi.encodePacked(header, elementHeader, keccak256("commitments"), mandateHash);
    }

    /// @notice Create Compact data with specific expires
    function _createCompactDataWithExpires(uint256 expires) internal returns (bytes memory) {
        bytes memory header = abi.encodePacked(uint256(1), expires, uint256(0));
        bytes memory elementHeader = _createElementHeader(makeAddr("arbiter"), 0);
        bytes32 mandateHash = _computeBasicMandateHash();
        return abi.encodePacked(header, elementHeader, keccak256("commitments"), mandateHash);
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
        uint256 tokenData = (uint256(uint96(lockTag)) << 160) | uint256(uint160(token));
        bytes memory tokenInData = abi.encodePacked(uint8(1), tokenData, amount);
        bytes32 mandateHash = _computeBasicMandateHash();
        return abi.encodePacked(header, elementHeader, tokenInData, mandateHash);
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
        bytes memory targetData = abi.encodePacked(
            recipient,
            targetChainId,
            uint256(block.timestamp + 7200),
            Constants.EMPTY_TOKEN_OUT_HASH
        );
        bytes memory mandateFooter = _createMandateFooter();
        return abi.encodePacked(
            header, elementHeader, keccak256("commitments"), targetData, mandateFooter
        );
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
        bytes memory targetData = abi.encodePacked(
            makeAddr("recipient"), targetChainId, fillExpiry, Constants.EMPTY_TOKEN_OUT_HASH
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
        uint256 tokenData = uint256(uint160(token));
        bytes memory targetData = abi.encodePacked(
            makeAddr("recipient"),
            targetChainId,
            uint256(block.timestamp + 7200),
            uint8(1),
            tokenData,
            amount
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
        bytes32 targetHash = keccak256("target");
        bytes memory mandateData = abi.encodePacked(
            targetHash,
            block.chainid,
            uint128(0),
            originOpsHash,
            Constants.NO_OPS,
            keccak256("qualification")
        );
        return abi.encodePacked(header, elementHeader, keccak256("commitments"), mandateData);
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
        bytes32 targetHash = keccak256("target");
        bytes memory mandateData = abi.encodePacked(
            targetHash,
            targetChainId,
            uint128(0),
            Constants.NO_OPS,
            destOpsHash,
            keccak256("qualification")
        );
        return abi.encodePacked(header, elementHeader, keccak256("commitments"), mandateData);
    }

    /// @notice Create Compact data with qualification
    /// @notice Create Compact data with qualification for STORAGE/CATCHALL mode
    function _createCompactDataWithQualificationStorage(bytes32 qualHash)
        internal
        returns (bytes memory)
    {
        bytes memory header = _createCompactHeader();
        bytes memory elementHeader = _createElementHeader(makeAddr("arbiter"), 0);

        // Create qualification data that hashes to qualHash
        // For testing, we use qualHash as the data itself (32 bytes)
        // The rule checks bytes[0:32] == qualHash, so data must BE qualHash
        bytes memory qualificationData = abi.encodePacked(qualHash);

        // Storage format: [dataLength: 32][data: dataLength]
        bytes memory qualificationEncoded = abi.encodePacked(
            uint256(qualificationData.length), // 32 bytes length prefix
            qualificationData // the actual data
        );

        bytes memory mandateData = abi.encodePacked(
            keccak256("target"), // targetHash
            uint256(block.chainid), // targetChainId
            uint128(0), // minGas
            Constants.NO_OPS, // originOpsHash
            Constants.NO_OPS, // destOpsHash
            qualificationEncoded // qualification (expanded)
        );

        return abi.encodePacked(header, elementHeader, keccak256("commitments"), mandateData);
    }

    /// @notice Create Compact data with qualification for SUBPOLICY mode
    function _createCompactDataWithQualificationSubpolicy(bytes32 qualHash)
        internal
        returns (bytes memory)
    {
        bytes memory header = _createCompactHeader();
        bytes memory elementHeader = _createElementHeader(makeAddr("arbiter"), 0);

        // Create qualification data
        bytes memory qualificationData = abi.encodePacked(qualHash);

        // Subpolicy format: [flags: 1][dataLength: 32][data: dataLength]
        bytes memory qualificationEncoded = abi.encodePacked(
            uint8(0), // flags (0 = use keccak256)
            uint256(qualificationData.length), // 32 bytes length prefix
            qualificationData // the actual data
        );

        bytes memory mandateData = abi.encodePacked(
            keccak256("target"), // targetHash
            uint256(block.chainid), // targetChainId
            uint128(0), // minGas
            Constants.NO_OPS, // originOpsHash
            Constants.NO_OPS, // destOpsHash
            qualificationEncoded // qualification (expanded with flags)
        );

        return abi.encodePacked(header, elementHeader, keccak256("commitments"), mandateData);
    }

    /// @notice Create Compact data with multiple fields
    function _createCompactDataWithMultipleFields(
        address arbiter,
        address recipient,
        address tokenOut,
        uint256 targetChainId
    )
        internal
        view
        returns (bytes memory)
    {
        bytes memory header = _createCompactHeader();
        bytes memory elementHeader = _createElementHeader(arbiter, 0);
        uint256 tokenData = uint256(uint160(tokenOut));
        bytes memory targetData = abi.encodePacked(
            recipient,
            targetChainId,
            uint256(block.timestamp + 7200),
            uint8(1),
            tokenData,
            uint256(1000)
        );
        bytes memory mandateFooter = _createMandateFooter();
        return abi.encodePacked(
            header, elementHeader, keccak256("commitments"), targetData, mandateFooter
        );
    }

    /*//////////////////////////////////////////////////////////////
                         HASH COMPUTATION HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Compute expected hash for Compact (fast path)
    function computeExpectedHash(bytes calldata compactData) external view returns (bytes32) {
        uint256 nonce = uint256(bytes32(compactData[0:32]));
        uint256 expires = uint256(bytes32(compactData[32:64]));
        uint256 otherElementsLength = uint256(bytes32(compactData[64:96]));
        bytes32[] calldata otherElements;
        assembly {
            otherElements.offset := add(compactData.offset, 96)
            otherElements.length := otherElementsLength
        }
        uint256 offset = 96 + otherElementsLength * 32;
        address arbiter = address(bytes20(compactData[offset:offset + 20]));
        offset += 20;
        uint256 elementIndex = uint256(bytes32(compactData[offset:offset + 32]));
        offset += 32;
        bytes32 commitmentsHash = bytes32(compactData[offset:offset + 32]);
        offset += 32;
        bytes32 mandateHash = bytes32(compactData[offset:offset + 32]);
        bytes32 elementHash =
            EIP712TypeHashLib.hashElementRaw(arbiter, block.chainid, commitmentsHash, mandateHash);
        bytes32 allElementsHash = otherElements.insertAtAndHash(elementIndex, elementHash);
        return EIP712TypeHashLib.hashCompact(testAccount, nonce, expires, allElementsHash);
    }

    /// @notice Compute expected hash when target is expanded
    function computeExpectedHashWithTarget(bytes calldata compactData)
        external
        view
        returns (bytes32)
    {
        uint256 nonce = uint256(bytes32(compactData[0:32]));
        uint256 expires = uint256(bytes32(compactData[32:64]));
        uint256 otherElementsLength = uint256(bytes32(compactData[64:96]));
        bytes32[] calldata otherElements;
        assembly {
            otherElements.offset := add(compactData.offset, 96)
            otherElements.length := otherElementsLength
        }
        uint256 offset = 96 + otherElementsLength * 32;
        address arbiter = address(bytes20(compactData[offset:offset + 20]));
        offset += 20;
        uint256 elementIndex = uint256(bytes32(compactData[offset:offset + 32]));
        offset += 32;
        bytes32 commitmentsHash = bytes32(compactData[offset:offset + 32]);
        offset += 32;
        address recipient = address(bytes20(compactData[offset:offset + 20]));
        offset += 20;
        uint256 targetChainId = uint256(bytes32(compactData[offset:offset + 32]));
        offset += 32;
        uint256 fillExpiry = uint256(bytes32(compactData[offset:offset + 32]));
        offset += 32;
        bytes32 tokenOutHash = bytes32(compactData[offset:offset + 32]);
        offset += 32;
        bytes32 targetHash = EIP712TypeHashLib.hashTargetAttributesRaw(
            recipient, tokenOutHash, targetChainId, fillExpiry
        );
        uint128 minGas = uint128(bytes16(compactData[offset:offset + 16]));
        offset += 16;
        bytes32 originOpsHash = bytes32(compactData[offset:offset + 32]);
        offset += 32;
        bytes32 destOpsHash = bytes32(compactData[offset:offset + 32]);
        offset += 32;
        bytes32 qualificationHash = bytes32(compactData[offset:offset + 32]);
        bytes32 mandateHash = EIP712TypeHashLib.hashMandateRaw(
            targetHash, minGas, originOpsHash, destOpsHash, qualificationHash
        );
        bytes32 elementHash =
            EIP712TypeHashLib.hashElementRaw(arbiter, block.chainid, commitmentsHash, mandateHash);
        bytes32 allElementsHash = otherElements.insertAtAndHash(elementIndex, elementHash);
        return EIP712TypeHashLib.hashCompact(testAccount, nonce, expires, allElementsHash);
    }

    /// @notice Compute expected hash when tokenIn is expanded
    function computeExpectedHashWithTokenIn(bytes calldata compactData)
        external
        view
        returns (bytes32)
    {
        uint256 nonce = uint256(bytes32(compactData[0:32]));
        uint256 expires = uint256(bytes32(compactData[32:64]));
        uint256 otherElementsLength = uint256(bytes32(compactData[64:96]));
        bytes32[] calldata otherElements;
        assembly {
            otherElements.offset := add(compactData.offset, 96)
            otherElements.length := otherElementsLength
        }
        uint256 offset = 96 + otherElementsLength * 32;
        address arbiter = address(bytes20(compactData[offset:offset + 20]));
        offset += 20;
        uint256 elementIndex = uint256(bytes32(compactData[offset:offset + 32]));
        offset += 32;
        uint8 tokenInLength = uint8(compactData[offset]);
        offset += 1;
        uint256[2][] calldata tokenIn;
        assembly {
            tokenIn.offset := add(compactData.offset, offset)
            tokenIn.length := tokenInLength
        }
        bytes32 commitmentsHash = EIP712TypeHashLib.hashTokenIn(tokenIn);
        offset += uint256(tokenInLength) * 64;
        bytes32 mandateHash = bytes32(compactData[offset:offset + 32]);
        bytes32 elementHash =
            EIP712TypeHashLib.hashElementRaw(arbiter, block.chainid, commitmentsHash, mandateHash);
        bytes32 allElementsHash = otherElements.insertAtAndHash(elementIndex, elementHash);
        return EIP712TypeHashLib.hashCompact(testAccount, nonce, expires, allElementsHash);
    }

    /// @notice Compute expected hash when tokenOut is expanded
    function computeExpectedHashWithTokenOut(bytes calldata compactData)
        external
        view
        returns (bytes32)
    {
        uint256 nonce = uint256(bytes32(compactData[0:32]));
        uint256 expires = uint256(bytes32(compactData[32:64]));
        uint256 otherElementsLength = uint256(bytes32(compactData[64:96]));
        bytes32[] calldata otherElements;
        assembly {
            otherElements.offset := add(compactData.offset, 96)
            otherElements.length := otherElementsLength
        }
        uint256 offset = 96 + otherElementsLength * 32;
        address arbiter = address(bytes20(compactData[offset:offset + 20]));
        offset += 20;
        uint256 elementIndex = uint256(bytes32(compactData[offset:offset + 32]));
        offset += 32;
        bytes32 commitmentsHash = bytes32(compactData[offset:offset + 32]);
        offset += 32;
        address recipient = address(bytes20(compactData[offset:offset + 20]));
        offset += 20;
        uint256 targetChainId = uint256(bytes32(compactData[offset:offset + 32]));
        offset += 32;
        uint256 fillExpiry = uint256(bytes32(compactData[offset:offset + 32]));
        offset += 32;
        uint8 tokenOutLength = uint8(compactData[offset]);
        offset += 1;
        uint256[2][] calldata tokenOut;
        assembly {
            tokenOut.offset := add(compactData.offset, offset)
            tokenOut.length := tokenOutLength
        }
        bytes32 tokenOutHash = EIP712TypeHashLib.hashTokenOut(tokenOut);
        offset += uint256(tokenOutLength) * 64;
        bytes32 targetHash = EIP712TypeHashLib.hashTargetAttributesRaw(
            recipient, tokenOutHash, targetChainId, fillExpiry
        );
        uint128 minGas = uint128(bytes16(compactData[offset:offset + 16]));
        offset += 16;
        bytes32 originOpsHash = bytes32(compactData[offset:offset + 32]);
        offset += 32;
        bytes32 destOpsHash = bytes32(compactData[offset:offset + 32]);
        offset += 32;
        bytes32 qualificationHash = bytes32(compactData[offset:offset + 32]);
        bytes32 mandateHash = EIP712TypeHashLib.hashMandateRaw(
            targetHash, minGas, originOpsHash, destOpsHash, qualificationHash
        );
        bytes32 elementHash =
            EIP712TypeHashLib.hashElementRaw(arbiter, block.chainid, commitmentsHash, mandateHash);
        bytes32 allElementsHash = otherElements.insertAtAndHash(elementIndex, elementHash);
        return EIP712TypeHashLib.hashCompact(testAccount, nonce, expires, allElementsHash);
    }

    /// @notice Compute expected hash when mandate is expanded
    function computeExpectedHashWithMandateExpanded(bytes calldata compactData)
        external
        view
        returns (bytes32)
    {
        uint256 nonce = uint256(bytes32(compactData[0:32]));
        uint256 expires = uint256(bytes32(compactData[32:64]));
        uint256 otherElementsLength = uint256(bytes32(compactData[64:96]));
        bytes32[] calldata otherElements;
        assembly {
            otherElements.offset := add(compactData.offset, 96)
            otherElements.length := otherElementsLength
        }
        uint256 offset = 96 + otherElementsLength * 32;
        address arbiter = address(bytes20(compactData[offset:offset + 20]));
        offset += 20;
        uint256 elementIndex = uint256(bytes32(compactData[offset:offset + 32]));
        offset += 32;
        bytes32 commitmentsHash = bytes32(compactData[offset:offset + 32]);
        offset += 32;
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
        bytes32 mandateHash = EIP712TypeHashLib.hashMandateRaw(
            targetHash, minGas, originOpsHash, destOpsHash, qualificationHash
        );
        bytes32 elementHash =
            EIP712TypeHashLib.hashElementRaw(arbiter, block.chainid, commitmentsHash, mandateHash);
        bytes32 allElementsHash = otherElements.insertAtAndHash(elementIndex, elementHash);
        return EIP712TypeHashLib.hashCompact(testAccount, nonce, expires, allElementsHash);
    }

    /// @notice Compute expected hash when mandate is expanded with qualification data
    function computeExpectedHashWithQualificationExpanded(bytes calldata compactData)
        external
        view
        returns (bytes32)
    {
        uint256 nonce = uint256(bytes32(compactData[0:32]));
        uint256 expires = uint256(bytes32(compactData[32:64]));
        uint256 otherElementsLength = uint256(bytes32(compactData[64:96]));
        bytes32[] calldata otherElements;
        assembly {
            otherElements.offset := add(compactData.offset, 96)
            otherElements.length := otherElementsLength
        }
        uint256 offset = 96 + otherElementsLength * 32;
        address arbiter = address(bytes20(compactData[offset:offset + 20]));
        offset += 20;
        uint256 elementIndex = uint256(bytes32(compactData[offset:offset + 32]));
        offset += 32;
        bytes32 commitmentsHash = bytes32(compactData[offset:offset + 32]);
        offset += 32;
        bytes32 targetHash = bytes32(compactData[offset:offset + 32]);
        offset += 32;
        offset += 32; // skip targetChainId
        uint128 minGas = uint128(bytes16(compactData[offset:offset + 16]));
        offset += 16;
        bytes32 originOpsHash = bytes32(compactData[offset:offset + 32]);
        offset += 32;
        bytes32 destOpsHash = bytes32(compactData[offset:offset + 32]);
        offset += 32;

        // For storage/catchall: [dataLength: 32][data: dataLength]
        uint256 dataLength = uint256(bytes32(compactData[offset:offset + 32]));
        offset += 32;
        bytes32 qualificationHash = keccak256(compactData[offset:offset + dataLength]);

        bytes32 mandateHash = EIP712TypeHashLib.hashMandateRaw(
            targetHash, minGas, originOpsHash, destOpsHash, qualificationHash
        );
        bytes32 elementHash =
            EIP712TypeHashLib.hashElementRaw(arbiter, block.chainid, commitmentsHash, mandateHash);
        bytes32 allElementsHash = otherElements.insertAtAndHash(elementIndex, elementHash);
        return EIP712TypeHashLib.hashCompact(testAccount, nonce, expires, allElementsHash);
    }

    /// @notice Compute expected hash when mandate is expanded with qualification data (subpolicy
    /// format)
    function computeExpectedHashWithQualificationSubpolicy(bytes calldata compactData)
        external
        view
        returns (bytes32)
    {
        uint256 nonce = uint256(bytes32(compactData[0:32]));
        uint256 expires = uint256(bytes32(compactData[32:64]));
        uint256 otherElementsLength = uint256(bytes32(compactData[64:96]));
        bytes32[] calldata otherElements;
        assembly {
            otherElements.offset := add(compactData.offset, 96)
            otherElements.length := otherElementsLength
        }
        uint256 offset = 96 + otherElementsLength * 32;
        address arbiter = address(bytes20(compactData[offset:offset + 20]));
        offset += 20;
        uint256 elementIndex = uint256(bytes32(compactData[offset:offset + 32]));
        offset += 32;
        bytes32 commitmentsHash = bytes32(compactData[offset:offset + 32]);
        offset += 32;
        bytes32 targetHash = bytes32(compactData[offset:offset + 32]);
        offset += 32;
        offset += 32; // skip targetChainId
        uint128 minGas = uint128(bytes16(compactData[offset:offset + 16]));
        offset += 16;
        bytes32 originOpsHash = bytes32(compactData[offset:offset + 32]);
        offset += 32;
        bytes32 destOpsHash = bytes32(compactData[offset:offset + 32]);
        offset += 32;

        // For subpolicy: [flags: 1][dataLength: 32][data: dataLength]
        offset += 1; // skip flags
        uint256 dataLength = uint256(bytes32(compactData[offset:offset + 32]));
        offset += 32;
        bytes32 qualificationHash = keccak256(compactData[offset:offset + dataLength]);

        bytes32 mandateHash = EIP712TypeHashLib.hashMandateRaw(
            targetHash, minGas, originOpsHash, destOpsHash, qualificationHash
        );
        bytes32 elementHash =
            EIP712TypeHashLib.hashElementRaw(arbiter, block.chainid, commitmentsHash, mandateHash);
        bytes32 allElementsHash = otherElements.insertAtAndHash(elementIndex, elementHash);
        return EIP712TypeHashLib.hashCompact(testAccount, nonce, expires, allElementsHash);
    }
}
