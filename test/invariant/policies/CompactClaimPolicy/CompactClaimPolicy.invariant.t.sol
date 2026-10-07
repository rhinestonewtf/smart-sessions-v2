// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { StdInvariant } from "forge-std/StdInvariant.sol";
import {
    CompactClaimPolicy_Unit_Test
} from "@test/unit/policies/claim/CompactClaimPolicy/CompactClaimPolicy.t.sol";

// Libraries
import { EIP712TypeHashLib } from "@compact-utils/types/EIP712TypeHashLib.sol";
import { DomainLib } from "@the-compact/lib/DomainLib.sol";
import { EfficientHashLib } from "@solady/utils/EfficientHashLib.sol";
import { Bytes32ArrayLib } from "@rhinestone/compact-utils/src/common/Bytes32ArrayLib.sol";
import { BaseConfigLib } from "@policies/claim/base/lib/BaseConfigLib.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import { PolicyConfig } from "@policies/claim/base/types/BaseDataTypes.sol";
import {
    MODE_CHECK_STORAGE,
    FIELD_ARBITER,
    FIELD_EXPIRY,
    FIELD_TOKEN_IN,
    FIELD_RECIPIENT,
    FIELD_FILL_EXPIRY,
    FIELD_TOKEN_OUT,
    FIELD_ORIGIN_OPS,
    FIELD_DEST_OPS,
    FIELD_RECIPIENT_IS_SPONSOR
} from "@policies/claim/base/types/BaseDataTypes.sol";
import { Constants } from "@compact-utils/types/Constants.sol";

/*//////////////////////////////////////////////////////////////
                              HANDLER
//////////////////////////////////////////////////////////////*/

/// @title CompactClaimPolicyHandler
/// @notice Handler contract for invariant testing of CompactClaimPolicy.check1271SignedAction
/// @dev Tests three simple invariants without reimplementing validation logic:
///      1. Valid config + valid data → true
///      2. Valid config + wrong hash → false
///      3. Valid config + one invalid field → false
contract CompactClaimPolicyHandler is CompactClaimPolicy_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using EfficientHashLib for bytes32[];
    using Bytes32ArrayLib for bytes32[];
    using BaseConfigLib for PolicyConfig;

    /*//////////////////////////////////////////////////////////////
                                CONSTANTS
    //////////////////////////////////////////////////////////////*/

    bytes32 internal constant SAMPLE_QUALIFICATION_HASH = keccak256("qualification");
    bytes12 internal constant DEFAULT_LOCK_TAG = bytes12(0);
    uint256 internal constant TARGET_CHAIN_ID = 137;

    /// @dev keccak256("Lock(bytes12 lockTag,address token,uint256 amount)")
    bytes32 internal constant TYPEHASH_LOCK =
        0xfb7744571d97aa61eb9c2bc3c67b9b1ba047ac9e95afb2ef02bc5b3d9e64fbe5;

    /// @dev keccak256("Token(address token,uint256 amount)")
    bytes32 internal constant TYPEHASH_TOKENOUT =
        0x55550a068ac7a6c7ce02eac46ebe7c7b964dd10d7800455df1c5bc5a6685a42c;

    /*//////////////////////////////////////////////////////////////
                            GHOST VARIABLES
    //////////////////////////////////////////////////////////////*/

    uint256 public ghost_configureCount;

    /// @notice Invariant 1: Valid data should pass
    uint256 public ghost_validDataPassed;
    uint256 public ghost_validDataFailed;

    /// @notice Invariant 2: Wrong hash should fail
    uint256 public ghost_wrongHashPassed;
    uint256 public ghost_wrongHashFailed;

    /// @notice Invariant 3: Invalid field should fail
    uint256 public ghost_invalidFieldPassed;
    uint256 public ghost_invalidFieldFailed;

    string public last_failReason;

    /*//////////////////////////////////////////////////////////////
                         CONFIGURED FIELD STATE
    //////////////////////////////////////////////////////////////*/

    address public cfg_arbiter;
    uint128 public cfg_expiryMin;
    uint128 public cfg_expiryMax;
    uint256 public cfg_tokenInCompactId;
    address public cfg_recipient;
    uint128 public cfg_fillExpiryMin;
    uint128 public cfg_fillExpiryMax;
    address public cfg_tokenOut;
    bool public cfg_originOpsRequired;
    bool public cfg_destOpsRequired;

    /*//////////////////////////////////////////////////////////////
                                VARIABLES
    //////////////////////////////////////////////////////////////*/

    address internal handlerTestAccount;
    ConfigId internal handlerTestConfigId;
    bytes32 internal handlerDomainSeparator =
        0x1234567890123456789012345678901234567890123456789012345678901234;
    address internal cfg_sponsor;

    /*//////////////////////////////////////////////////////////////
                              TEST DATA
    //////////////////////////////////////////////////////////////*/

    struct TestData {
        address arbiter;
        uint256 nonce;
        uint256 expires;
        uint256 tokenInCompactId;
        uint256 tokenInAmount;
        address recipient;
        uint256 fillExpiry;
        address tokenOut;
        uint256 tokenOutAmount;
        bytes32 originOpsHash;
        bytes32 destOpsHash;
    }

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        super.setUp();

        handlerTestAccount = makeAddr("handlerTestAccount");
        handlerTestConfigId = ConfigId.wrap(bytes32(uint256(1)));
        cfg_sponsor = admin.addr;
    }

    /*//////////////////////////////////////////////////////////////
                         HANDLER: CONFIGURE
    //////////////////////////////////////////////////////////////*/

    /// @notice Configure policy with arbitrary field combination
    /// @param fieldBitmask Bitmask of fields to enable (bit N = FIELD N)
    /// @param seed Random seed for generating config values
    function handler_configure(uint16 fieldBitmask, uint256 seed) external {
        // Skip if already configured (don't overwrite cfg_* values)
        PolicyConfig modeConfig =
            compactClaimPolicy.getModeConfig(handlerTestConfigId, handlerTestAccount);
        if (PolicyConfig.unwrap(modeConfig) != 0) return;

        // Bound to valid field bits, exclude QUALIFICATION (bit 8)
        fieldBitmask = fieldBitmask & 0x2FF;

        // Skip if no fields enabled
        if (fieldBitmask == 0) return;

        // Per-chain destOps requires a target check (DestOpsRequiresTargetCheck); force the
        // data-free recipientIsSponsor check so the fuzzer keeps exercising destOps configs.
        uint16 targetCheckBits = uint16(
            (1 << FIELD_RECIPIENT) | (1 << FIELD_FILL_EXPIRY) | (1 << FIELD_TOKEN_OUT)
                | (1 << FIELD_RECIPIENT_IS_SPONSOR)
        );
        if ((fieldBitmask & (1 << FIELD_DEST_OPS)) != 0 && (fieldBitmask & targetCheckBits) == 0) {
            fieldBitmask |= uint16(1 << FIELD_RECIPIENT_IS_SPONSOR);
        }

        // Generate config values from seed
        _generateConfigValues(seed);

        // Build and apply init data
        bytes memory initData = _buildInitData(fieldBitmask);
        compactClaimPolicy.initializeWithMultiplexer(
            handlerTestAccount, handlerTestConfigId, initData
        );

        ghost_configureCount++;
    }

    /*//////////////////////////////////////////////////////////////
              INVARIANT 1: VALID DATA SHOULD RETURN TRUE
    //////////////////////////////////////////////////////////////*/

    /// @notice Test that valid config + valid data returns true
    /// @param seed Random seed for data generation
    function handler_checkValidData(uint256 seed) external {
        PolicyConfig modeConfig =
            compactClaimPolicy.getModeConfig(handlerTestConfigId, handlerTestAccount);

        // Skip if not configured
        if (PolicyConfig.unwrap(modeConfig) == 0) return;

        // Generate all valid data
        TestData memory data = _generateValidData(modeConfig, seed);

        // Build compact calldata
        bytes memory compactData = _buildCompactData(modeConfig, data);

        // Compute correct hash
        bytes32 computedHash = this.computeHash(
            compactData,
            modeConfig.hasCheckTokenIn(),
            modeConfig.hasAnyTargetCheck(),
            modeConfig.hasCheckTokenOut()
        );
        bytes32 withDomain = DomainLib.withDomain(computedHash, handlerDomainSeparator);

        // Execute check
        bool result = compactClaimPolicy.check1271SignedAction(
            handlerTestConfigId,
            cfg_sponsor,
            handlerTestAccount,
            withDomain,
            abi.encodePacked(handlerDomainSeparator, compactData)
        );

        // Record result
        if (result) {
            ghost_validDataPassed++;
        } else {
            ghost_validDataFailed++;
            last_failReason = "Valid data should return TRUE";
        }
    }

    /*//////////////////////////////////////////////////////////////
              INVARIANT 2: WRONG HASH SHOULD RETURN FALSE
    //////////////////////////////////////////////////////////////*/

    /// @notice Test that wrong hash always returns false
    /// @param seed Random seed for data generation
    function handler_checkWrongHash(uint256 seed) external {
        PolicyConfig modeConfig =
            compactClaimPolicy.getModeConfig(handlerTestConfigId, handlerTestAccount);

        // Skip if not configured
        if (PolicyConfig.unwrap(modeConfig) == 0) return;

        // Generate valid data
        TestData memory data = _generateValidData(modeConfig, seed);

        // Build compact calldata
        bytes memory compactData = _buildCompactData(modeConfig, data);

        // Use completely wrong hash
        bytes32 wrongHash = keccak256(abi.encodePacked("wrong", seed));

        // Execute check
        bool result = compactClaimPolicy.check1271SignedAction(
            handlerTestConfigId,
            cfg_sponsor,
            handlerTestAccount,
            wrongHash,
            abi.encodePacked(handlerDomainSeparator, compactData)
        );

        // Record result
        if (result) {
            ghost_wrongHashPassed++;
            last_failReason = "Wrong hash should return FALSE";
        } else {
            ghost_wrongHashFailed++;
        }
    }

    /*//////////////////////////////////////////////////////////////
           INVARIANT 3: ONE INVALID FIELD SHOULD RETURN FALSE
    //////////////////////////////////////////////////////////////*/

    /// @notice Test that one invalid field causes check to fail
    /// @param seed Random seed for data generation
    /// @param fieldHint Hint for which field to invalidate
    function handler_checkOneInvalidField(uint256 seed, uint8 fieldHint) external {
        PolicyConfig modeConfig =
            compactClaimPolicy.getModeConfig(handlerTestConfigId, handlerTestAccount);

        // Skip if not configured
        if (PolicyConfig.unwrap(modeConfig) == 0) return;

        // Pick an enabled field to invalidate
        uint8 field = _pickEnabledField(modeConfig, fieldHint);
        if (field == type(uint8).max) return;

        // Generate valid data, then invalidate one field
        TestData memory data = _generateValidData(modeConfig, seed);
        _invalidateField(data, field, seed);

        // Build compact calldata with invalidated data
        bytes memory compactData = _buildCompactData(modeConfig, data);

        // Compute hash for the invalidated data
        bytes32 computedHash = this.computeHash(
            compactData,
            modeConfig.hasCheckTokenIn(),
            modeConfig.hasAnyTargetCheck(),
            modeConfig.hasCheckTokenOut()
        );
        bytes32 withDomain = DomainLib.withDomain(computedHash, handlerDomainSeparator);

        // Execute check
        bool result = compactClaimPolicy.check1271SignedAction(
            handlerTestConfigId,
            cfg_sponsor,
            handlerTestAccount,
            withDomain,
            abi.encodePacked(handlerDomainSeparator, compactData)
        );

        // Record result
        if (result) {
            ghost_invalidFieldPassed++;
            last_failReason =
                string.concat("Invalid field ", _fieldName(field), " should return FALSE");
        } else {
            ghost_invalidFieldFailed++;
        }
    }

    /*//////////////////////////////////////////////////////////////
                          DATA GENERATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Generate config values from seed
    function _generateConfigValues(uint256 seed) internal {
        uint256 s = seed;

        cfg_arbiter = _seedToAddress(s++);
        cfg_expiryMin = uint128(s++ % 1_000_000);
        cfg_expiryMax = cfg_expiryMin + uint128(s++ % 1_000_000) + 1;
        cfg_tokenInCompactId =
            (uint256(uint96(DEFAULT_LOCK_TAG)) << 160) | uint256(uint160(_seedToAddress(s++)));
        cfg_recipient = _seedToAddress(s++);
        cfg_fillExpiryMin = uint128(s++ % 1_000_000);
        cfg_fillExpiryMax = cfg_fillExpiryMin + uint128(s++ % 1_000_000) + 1;
        cfg_tokenOut = _seedToAddress(s++);
        cfg_originOpsRequired = (s++ % 2) == 1;
        cfg_destOpsRequired = (s++ % 2) == 1;
    }

    /// @notice Generate data that's valid for all enabled checks
    function _generateValidData(
        PolicyConfig modeConfig,
        uint256 seed
    )
        internal
        view
        returns (TestData memory data)
    {
        uint256 s = seed;

        // Use configured values for checked fields, random for unchecked
        data.arbiter = modeConfig.hasCheckArbiter() ? cfg_arbiter : _seedToAddress(s++);
        data.nonce = s++;
        data.expires = modeConfig.hasCheckExpiry()
            ? cfg_expiryMin + ((cfg_expiryMax - cfg_expiryMin) / 2)
            : block.timestamp + 3600;
        data.tokenInCompactId = modeConfig.hasCheckTokenIn()
            ? cfg_tokenInCompactId
            : uint256(uint160(_seedToAddress(s++)));
        data.tokenInAmount = 1000 + (s++ % 10_000);

        // Recipient: check RECIPIENT_IS_SPONSOR first, then RECIPIENT
        if (modeConfig.hasCheckRecipientIsSponsor()) {
            data.recipient = handlerTestAccount;
        } else if (modeConfig.hasCheckRecipient()) {
            data.recipient = cfg_recipient;
        } else {
            data.recipient = _seedToAddress(s++);
        }

        data.fillExpiry = modeConfig.hasCheckFillExpiry()
            ? cfg_fillExpiryMin + ((cfg_fillExpiryMax - cfg_fillExpiryMin) / 2)
            : block.timestamp + 7200;
        data.tokenOut = modeConfig.hasCheckTokenOut() ? cfg_tokenOut : _seedToAddress(s++);
        data.tokenOutAmount = 500 + (s++ % 5000);

        // Ops checks
        data.originOpsHash = modeConfig.hasCheckOriginOps()
            ? (cfg_originOpsRequired ? keccak256("ops") : Constants.NO_OPS)
            : Constants.NO_OPS;
        data.destOpsHash = modeConfig.hasCheckDestOps()
            ? (cfg_destOpsRequired ? keccak256("destOps") : Constants.NO_OPS)
            : Constants.NO_OPS;
    }

    /// @notice Invalidate a specific field in the test data
    function _invalidateField(TestData memory data, uint8 field, uint256 seed) internal view {
        if (field == FIELD_ARBITER) {
            data.arbiter = _seedToAddress(seed + 999);
        } else if (field == FIELD_EXPIRY) {
            data.expires = cfg_expiryMax + 1000;
        } else if (field == FIELD_TOKEN_IN) {
            data.tokenInCompactId = uint256(uint160(_seedToAddress(seed + 888)));
        } else if (field == FIELD_RECIPIENT) {
            data.recipient = _seedToAddress(seed + 777);
        } else if (field == FIELD_RECIPIENT_IS_SPONSOR) {
            data.recipient = _seedToAddress(seed + 666);
        } else if (field == FIELD_FILL_EXPIRY) {
            data.fillExpiry = cfg_fillExpiryMax + 1000;
        } else if (field == FIELD_TOKEN_OUT) {
            data.tokenOut = _seedToAddress(seed + 555);
        } else if (field == FIELD_ORIGIN_OPS) {
            data.originOpsHash = cfg_originOpsRequired ? Constants.NO_OPS : keccak256("ops");
        } else if (field == FIELD_DEST_OPS) {
            data.destOpsHash = cfg_destOpsRequired ? Constants.NO_OPS : keccak256("destOps");
        }
    }

    /*//////////////////////////////////////////////////////////////
                           FIELD HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Pick an enabled field to invalidate
    function _pickEnabledField(PolicyConfig modeConfig, uint8 hint) internal pure returns (uint8) {
        uint8[9] memory fields = [
            FIELD_ARBITER,
            FIELD_EXPIRY,
            FIELD_TOKEN_IN,
            FIELD_RECIPIENT,
            FIELD_FILL_EXPIRY,
            FIELD_TOKEN_OUT,
            FIELD_ORIGIN_OPS,
            FIELD_DEST_OPS,
            FIELD_RECIPIENT_IS_SPONSOR
        ];

        // Try starting from hint, wrap around
        for (uint8 i = 0; i < 9; i++) {
            uint8 idx = (hint + i) % 9;
            uint8 field = fields[idx];
            if (_isFieldEnabled(modeConfig, field)) {
                return field;
            }
        }

        return type(uint8).max; // No fields enabled
    }

    /// @notice Check if a field is enabled in the config
    function _isFieldEnabled(PolicyConfig modeConfig, uint8 field) internal pure returns (bool) {
        if (field == FIELD_ARBITER) return modeConfig.hasCheckArbiter();
        if (field == FIELD_EXPIRY) return modeConfig.hasCheckExpiry();
        if (field == FIELD_TOKEN_IN) return modeConfig.hasCheckTokenIn();
        if (field == FIELD_RECIPIENT) return modeConfig.hasCheckRecipient();
        if (field == FIELD_FILL_EXPIRY) return modeConfig.hasCheckFillExpiry();
        if (field == FIELD_TOKEN_OUT) return modeConfig.hasCheckTokenOut();
        if (field == FIELD_ORIGIN_OPS) return modeConfig.hasCheckOriginOps();
        if (field == FIELD_DEST_OPS) return modeConfig.hasCheckDestOps();
        if (field == FIELD_RECIPIENT_IS_SPONSOR) return modeConfig.hasCheckRecipientIsSponsor();
        return false;
    }

    /// @notice Get field name for error messages
    function _fieldName(uint8 field) internal pure returns (string memory) {
        if (field == FIELD_ARBITER) return "ARBITER";
        if (field == FIELD_EXPIRY) return "EXPIRY";
        if (field == FIELD_TOKEN_IN) return "TOKEN_IN";
        if (field == FIELD_RECIPIENT) return "RECIPIENT";
        if (field == FIELD_FILL_EXPIRY) return "FILL_EXPIRY";
        if (field == FIELD_TOKEN_OUT) return "TOKEN_OUT";
        if (field == FIELD_ORIGIN_OPS) return "ORIGIN_OPS";
        if (field == FIELD_DEST_OPS) return "DEST_OPS";
        if (field == FIELD_RECIPIENT_IS_SPONSOR) return "RECIPIENT_IS_SPONSOR";
        return "UNKNOWN";
    }

    /*//////////////////////////////////////////////////////////////
                            BUILD INIT DATA
    //////////////////////////////////////////////////////////////*/

    /// @notice Build initialization data for the policy
    function _buildInitData(uint16 fieldBitmask) internal view returns (bytes memory initData) {
        // Build modeConfig
        uint32 modeConfig;

        if ((fieldBitmask & (1 << FIELD_ARBITER)) != 0) {
            modeConfig |= uint32(MODE_CHECK_STORAGE) << (FIELD_ARBITER * 2);
        }
        if ((fieldBitmask & (1 << FIELD_EXPIRY)) != 0) {
            modeConfig |= uint32(MODE_CHECK_STORAGE) << (FIELD_EXPIRY * 2);
        }
        if ((fieldBitmask & (1 << FIELD_TOKEN_IN)) != 0) {
            modeConfig |= uint32(MODE_CHECK_STORAGE) << (FIELD_TOKEN_IN * 2);
        }
        if ((fieldBitmask & (1 << FIELD_RECIPIENT)) != 0) {
            modeConfig |= uint32(MODE_CHECK_STORAGE) << (FIELD_RECIPIENT * 2);
        }
        if ((fieldBitmask & (1 << FIELD_FILL_EXPIRY)) != 0) {
            modeConfig |= uint32(MODE_CHECK_STORAGE) << (FIELD_FILL_EXPIRY * 2);
        }
        if ((fieldBitmask & (1 << FIELD_TOKEN_OUT)) != 0) {
            modeConfig |= uint32(MODE_CHECK_STORAGE) << (FIELD_TOKEN_OUT * 2);
        }
        if ((fieldBitmask & (1 << FIELD_ORIGIN_OPS)) != 0) {
            modeConfig |= uint32(MODE_CHECK_STORAGE) << (FIELD_ORIGIN_OPS * 2);
        }
        if ((fieldBitmask & (1 << FIELD_DEST_OPS)) != 0) {
            modeConfig |= uint32(MODE_CHECK_STORAGE) << (FIELD_DEST_OPS * 2);
        }
        if ((fieldBitmask & (1 << FIELD_RECIPIENT_IS_SPONSOR)) != 0) {
            modeConfig |= uint32(MODE_CHECK_STORAGE) << (FIELD_RECIPIENT_IS_SPONSOR * 2);
        }

        // Build initData - fields must be in order!
        initData = abi.encodePacked(modeConfig);

        if ((fieldBitmask & (1 << FIELD_ARBITER)) != 0) {
            initData = abi.encodePacked(initData, uint8(1), cfg_arbiter);
        }
        if ((fieldBitmask & (1 << FIELD_EXPIRY)) != 0) {
            initData = abi.encodePacked(
                initData, uint256(cfg_expiryMin) | (uint256(cfg_expiryMax) << 128)
            );
        }
        if ((fieldBitmask & (1 << FIELD_TOKEN_IN)) != 0) {
            initData = abi.encodePacked(initData, uint8(1), block.chainid, cfg_tokenInCompactId);
        }
        if ((fieldBitmask & (1 << FIELD_RECIPIENT)) != 0) {
            initData = abi.encodePacked(initData, uint8(1), TARGET_CHAIN_ID, cfg_recipient);
        }
        if ((fieldBitmask & (1 << FIELD_FILL_EXPIRY)) != 0) {
            initData = abi.encodePacked(
                initData,
                uint8(1),
                TARGET_CHAIN_ID,
                uint256(cfg_fillExpiryMin) | (uint256(cfg_fillExpiryMax) << 128)
            );
        }
        if ((fieldBitmask & (1 << FIELD_TOKEN_OUT)) != 0) {
            initData = abi.encodePacked(initData, uint8(1), TARGET_CHAIN_ID, cfg_tokenOut);
        }
        if ((fieldBitmask & (1 << FIELD_ORIGIN_OPS)) != 0) {
            initData = abi.encodePacked(
                initData, uint8(1), block.chainid, uint8(cfg_originOpsRequired ? 1 : 0)
            );
        }
        if ((fieldBitmask & (1 << FIELD_DEST_OPS)) != 0) {
            initData = abi.encodePacked(
                initData, uint8(1), TARGET_CHAIN_ID, uint8(cfg_destOpsRequired ? 1 : 0)
            );
        }
        // RECIPIENT_IS_SPONSOR has no config data
    }

    /*//////////////////////////////////////////////////////////////
                          BUILD COMPACT DATA
    //////////////////////////////////////////////////////////////*/

    /// @notice Build compact calldata for the policy check
    function _buildCompactData(
        PolicyConfig modeConfig,
        TestData memory data
    )
        internal
        view
        returns (bytes memory)
    {
        // Header: nonce, expires, otherElementsLength
        bytes memory header = abi.encodePacked(data.nonce, data.expires, uint256(0));

        // Element header: arbiter, elementIndex
        bytes memory elementHeader = abi.encodePacked(data.arbiter, uint256(0));

        // TokenIn - format depends on whether it needs validation
        bytes memory tokenInData;
        if (modeConfig.hasCheckTokenIn()) {
            // Expanded: length + compactId + amount
            tokenInData = abi.encodePacked(uint8(1), data.tokenInCompactId, data.tokenInAmount);
        } else {
            // Fast path: pre-computed commitmentsHash (32 bytes)
            bytes12 lockTag = bytes12(uint96(data.tokenInCompactId >> 160));
            address token = address(uint160(data.tokenInCompactId));
            bytes32 lockHash =
                keccak256(abi.encode(TYPEHASH_LOCK, lockTag, token, data.tokenInAmount));
            bytes32 commitmentsHash = keccak256(abi.encodePacked(lockHash));
            tokenInData = abi.encodePacked(commitmentsHash);
        }

        // Mandate - format depends on whether target fields are checked
        bytes memory mandateData;
        if (modeConfig.hasAnyTargetCheck()) {
            // TokenOut format depends on whether FIELD_TOKEN_OUT is checked
            bytes memory tokenOutData;
            if (modeConfig.hasCheckTokenOut()) {
                // Expanded: length + [token, amount]
                tokenOutData = abi.encodePacked(
                    uint8(1), uint256(uint160(data.tokenOut)), data.tokenOutAmount
                );
            } else {
                // Pre-computed hash (32 bytes)
                bytes32 singleTokenOutHash =
                    keccak256(abi.encode(TYPEHASH_TOKENOUT, data.tokenOut, data.tokenOutAmount));
                bytes32 tokenOutHash = keccak256(abi.encodePacked(singleTokenOutHash));
                tokenOutData = abi.encodePacked(tokenOutHash);
            }

            // Expanded target: recipient, chainId, fillExpiry, tokenOut
            bytes memory targetData =
                abi.encodePacked(data.recipient, TARGET_CHAIN_ID, data.fillExpiry, tokenOutData);

            // Mandate footer
            mandateData = abi.encodePacked(
                targetData,
                uint128(0), // minGas
                data.originOpsHash,
                data.destOpsHash,
                SAMPLE_QUALIFICATION_HASH
            );
        } else {
            // Fast path: pre-computed mandateHash
            bytes32 mandateHash = EIP712TypeHashLib.hashMandateRaw(
                keccak256("target"),
                0,
                data.originOpsHash,
                data.destOpsHash,
                SAMPLE_QUALIFICATION_HASH
            );
            mandateData = abi.encodePacked(mandateHash);
        }

        return abi.encodePacked(header, elementHeader, tokenInData, mandateData);
    }

    /*//////////////////////////////////////////////////////////////
                    COMPUTE HASH (EXTERNAL FOR CALLDATA)
    //////////////////////////////////////////////////////////////*/

    /// @notice Compute hash by parsing compact data
    /// @dev External function to get calldata access for EIP712TypeHashLib functions
    function computeHash(
        bytes calldata compactData,
        bool hasTokenInCheck,
        bool hasTargetCheck,
        bool hasTokenOutCheck
    )
        external
        view
        returns (bytes32)
    {
        // Parse header
        uint256 nonce = uint256(bytes32(compactData[0:32]));
        uint256 expires = uint256(bytes32(compactData[32:64]));

        // Parse otherElements
        uint256 otherElementsLength = uint256(bytes32(compactData[64:96]));
        bytes32[] calldata otherElements;
        assembly {
            otherElements.offset := add(compactData.offset, 96)
            otherElements.length := otherElementsLength
        }
        uint256 offset = 96 + otherElementsLength * 32;

        // Parse element header
        address arbiter = address(bytes20(compactData[offset:offset + 20]));
        offset += 20;
        uint256 elementIndex = uint256(bytes32(compactData[offset:offset + 32]));
        offset += 32;

        // Parse tokenIn
        bytes32 commitmentsHash;
        if (hasTokenInCheck) {
            // Expanded: length + [compactId, amount][]
            uint8 tokenInLength = uint8(compactData[offset]);
            offset += 1;

            uint256[2][] calldata tokenIn;
            assembly {
                tokenIn.offset := add(compactData.offset, offset)
                tokenIn.length := tokenInLength
            }
            commitmentsHash = EIP712TypeHashLib.hashTokenIn(tokenIn);
            offset += uint256(tokenInLength) * 64;
        } else {
            // Fast path: pre-computed hash
            commitmentsHash = bytes32(compactData[offset:offset + 32]);
            offset += 32;
        }

        // Parse mandate
        bytes32 mandateHash;
        if (hasTargetCheck) {
            // Parse expanded target
            address recipient = address(bytes20(compactData[offset:offset + 20]));
            offset += 20;
            uint256 targetChainId = uint256(bytes32(compactData[offset:offset + 32]));
            offset += 32;
            uint256 fillExpiry = uint256(bytes32(compactData[offset:offset + 32]));
            offset += 32;

            // Parse tokenOut
            bytes32 tokenOutHash;
            if (hasTokenOutCheck) {
                // Expanded: length + [token, amount][]
                uint8 tokenOutLength = uint8(compactData[offset]);
                offset += 1;

                uint256[2][] calldata tokenOut;
                assembly {
                    tokenOut.offset := add(compactData.offset, offset)
                    tokenOut.length := tokenOutLength
                }
                tokenOutHash = EIP712TypeHashLib.hashTokenOut(tokenOut);
                offset += uint256(tokenOutLength) * 64;
            } else {
                // Pre-computed hash
                tokenOutHash = bytes32(compactData[offset:offset + 32]);
                offset += 32;
            }

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

            mandateHash = EIP712TypeHashLib.hashMandateRaw(
                targetHash, minGas, originOpsHash, destOpsHash, qualificationHash
            );
        } else {
            // Fast path: pre-computed mandateHash
            mandateHash = bytes32(compactData[offset:offset + 32]);
        }

        // Hash element
        bytes32 elementHash = EIP712TypeHashLib.hashElementRaw(
            arbiter, block.chainid, commitmentsHash, mandateHash
        );

        // Insert at index and hash
        bytes32 allElementsHash = otherElements.insertAtAndHash(elementIndex, elementHash);

        return EIP712TypeHashLib.hashCompact(handlerTestAccount, nonce, expires, allElementsHash);
    }

    /*//////////////////////////////////////////////////////////////
                            INTERNAL HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Convert seed to address
    function _seedToAddress(uint256 seed) internal pure returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked(seed)))));
    }
}

/*//////////////////////////////////////////////////////////////
                          INVARIANT TEST
//////////////////////////////////////////////////////////////*/

/// @title CompactClaimPolicy_check1271SignedAction_Invariant_Test
/// @notice Invariant tests for CompactClaimPolicy.check1271SignedAction
contract CompactClaimPolicy_check1271SignedAction_Invariant_Test is
    StdInvariant,
    CompactClaimPolicy_Unit_Test
{
    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    CompactClaimPolicyHandler public handler;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        super.setUp();

        handler = new CompactClaimPolicyHandler();
        handler.setUp();

        targetContract(address(handler));
        excludeContract(address(compactClaimPolicy));
        excludeContract(address(mockSubPolicy));
    }

    /*//////////////////////////////////////////////////////////////
                              INVARIANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Invariant 1: Valid config + valid data should always return true
    function invariant_validDataShouldPass() public view {
        assertEq(
            handler.ghost_validDataFailed(), 0, string.concat("FAIL: ", handler.last_failReason())
        );
    }

    /// @notice Invariant 2: Wrong hash should always return false
    function invariant_wrongHashShouldFail() public view {
        assertEq(
            handler.ghost_wrongHashPassed(), 0, string.concat("FAIL: ", handler.last_failReason())
        );
    }

    /// @notice Invariant 3: One invalid field should always return false
    function invariant_invalidFieldShouldFail() public view {
        assertEq(
            handler.ghost_invalidFieldPassed(),
            0,
            string.concat("FAIL: ", handler.last_failReason())
        );
    }
}
