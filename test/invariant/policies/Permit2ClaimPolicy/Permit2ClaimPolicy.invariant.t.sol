// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { StdInvariant } from "forge-std/StdInvariant.sol";
import {
    Permit2ClaimPolicy_Unit_Test
} from "@test/unit/policies/claim/Permit2ClaimPolicy/Permit2ClaimPolicy.t.sol";

// Contracts
import { Permit2EIP712 } from "@compact-utils/common/Permit2EIP712.sol";

// Libraries
import { EIP712TypeHashLib } from "@compact-utils/types/EIP712TypeHashLib.sol";
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

/// @title Permit2ClaimPolicyHandler
/// @notice Handler contract for invariant testing of Permit2ClaimPolicy.check1271SignedAction
/// @dev Tests three simple invariants without reimplementing validation logic:
///      1. Valid config + valid data → true
///      2. Valid config + wrong hash → false
///      3. Valid config + one invalid field → false
///
///      Key differences from CompactClaimPolicy:
///      - No domainSeparator in calldata
///      - No lockTag for tokenIn (just token addresses)
///      - Arbiter is Permit2 spender (at start of calldata)
///      - No elements array structure
///      - Uses block.chainid for tokenIn lookup
contract Permit2ClaimPolicyHandler is Permit2ClaimPolicy_Unit_Test, Permit2EIP712 {
    /*//////////////////////////////////////////////////////////////
                                LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using BaseConfigLib for PolicyConfig;

    /*//////////////////////////////////////////////////////////////
                                CONSTANTS
    //////////////////////////////////////////////////////////////*/

    bytes32 internal constant SAMPLE_QUALIFICATION_HASH = keccak256("qualification");
    uint256 internal constant TARGET_CHAIN_ID = 137;

    /// @dev keccak256("Token(address token,uint256 amount)")
    bytes32 internal constant TYPEHASH_TOKEN =
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
    address public cfg_tokenIn;
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
    address internal cfg_sponsor;

    /*//////////////////////////////////////////////////////////////
                              TEST DATA
    //////////////////////////////////////////////////////////////*/

    struct TestData {
        address arbiter;
        uint256 nonce;
        uint256 deadline;
        address tokenIn;
        uint256 tokenInAmount;
        address recipient;
        uint256 fillExpiry;
        address tokenOut;
        uint256 tokenOutAmount;
        bytes32 originOpsHash;
        bytes32 destOpsHash;
    }

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() Permit2EIP712(PERMIT2_ADDRESS) { }

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
            permit2ClaimPolicy.getModeConfig(handlerTestConfigId, handlerTestAccount);
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
        permit2ClaimPolicy.initializeWithMultiplexer(
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
            permit2ClaimPolicy.getModeConfig(handlerTestConfigId, handlerTestAccount);

        // Skip if not configured
        if (PolicyConfig.unwrap(modeConfig) == 0) return;

        // Generate all valid data
        TestData memory data = _generateValidData(modeConfig, seed);

        // Build permit2 calldata
        bytes memory permit2Data = _buildPermit2Data(modeConfig, data);

        // Compute correct hash (no domain separator wrapper for Permit2)
        bytes32 computedHash = this.computeHash(
            permit2Data,
            modeConfig.hasCheckTokenIn(),
            modeConfig.hasAnyTargetCheck(),
            modeConfig.hasCheckTokenOut()
        );

        // Execute check
        bool result = permit2ClaimPolicy.check1271SignedAction(
            handlerTestConfigId, cfg_sponsor, handlerTestAccount, computedHash, permit2Data
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
            permit2ClaimPolicy.getModeConfig(handlerTestConfigId, handlerTestAccount);

        // Skip if not configured
        if (PolicyConfig.unwrap(modeConfig) == 0) return;

        // Generate valid data
        TestData memory data = _generateValidData(modeConfig, seed);

        // Build permit2 calldata
        bytes memory permit2Data = _buildPermit2Data(modeConfig, data);

        // Use completely wrong hash
        bytes32 wrongHash = keccak256(abi.encodePacked("wrong", seed));

        // Execute check
        bool result = permit2ClaimPolicy.check1271SignedAction(
            handlerTestConfigId, cfg_sponsor, handlerTestAccount, wrongHash, permit2Data
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
            permit2ClaimPolicy.getModeConfig(handlerTestConfigId, handlerTestAccount);

        // Skip if not configured
        if (PolicyConfig.unwrap(modeConfig) == 0) return;

        // Pick an enabled field to invalidate
        uint8 field = _pickEnabledField(modeConfig, fieldHint);
        if (field == type(uint8).max) return;

        // Generate valid data, then invalidate one field
        TestData memory data = _generateValidData(modeConfig, seed);
        _invalidateField(data, field, seed);

        // Build permit2 calldata with invalidated data
        bytes memory permit2Data = _buildPermit2Data(modeConfig, data);

        // Compute hash for the invalidated data
        bytes32 computedHash = this.computeHash(
            permit2Data,
            modeConfig.hasCheckTokenIn(),
            modeConfig.hasAnyTargetCheck(),
            modeConfig.hasCheckTokenOut()
        );

        // Execute check
        bool result = permit2ClaimPolicy.check1271SignedAction(
            handlerTestConfigId, cfg_sponsor, handlerTestAccount, computedHash, permit2Data
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
        cfg_tokenIn = _seedToAddress(s++);
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
        data.deadline = modeConfig.hasCheckExpiry()
            ? cfg_expiryMin + ((cfg_expiryMax - cfg_expiryMin) / 2)
            : block.timestamp + 3600;
        data.tokenIn = modeConfig.hasCheckTokenIn() ? cfg_tokenIn : _seedToAddress(s++);
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
            data.deadline = cfg_expiryMax + 1000;
        } else if (field == FIELD_TOKEN_IN) {
            data.tokenIn = _seedToAddress(seed + 888);
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
            // Permit2: [count][chainId][token] - no lockTag
            initData = abi.encodePacked(initData, uint8(1), block.chainid, cfg_tokenIn);
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
                          BUILD PERMIT2 DATA
    //////////////////////////////////////////////////////////////*/

    /// @notice Build Permit2 calldata for the policy check
    /// @dev No domainSeparator prefix - Permit2 uses its own domain
    function _buildPermit2Data(
        PolicyConfig modeConfig,
        TestData memory data
    )
        internal
        view
        returns (bytes memory)
    {
        // Header: arbiter (20) + nonce (32) + deadline (32) = 84 bytes
        bytes memory header = abi.encodePacked(data.arbiter, data.nonce, data.deadline);

        // TokenIn - format depends on whether it needs validation
        bytes memory tokenInData;
        if (modeConfig.hasCheckTokenIn()) {
            // Expanded: length + [token (32), amount (32)]
            tokenInData =
                abi.encodePacked(uint8(1), uint256(uint160(data.tokenIn)), data.tokenInAmount);
        } else {
            // Fast path: pre-computed tokenPermissionsHash (32 bytes)
            bytes32 singleTokenHash =
                keccak256(abi.encode(TYPEHASH_TOKEN, data.tokenIn, data.tokenInAmount));
            bytes32 tokenPermissionsHash = keccak256(abi.encodePacked(singleTokenHash));
            tokenInData = abi.encodePacked(tokenPermissionsHash);
        }

        // Mandate - format depends on whether target fields are checked
        bytes memory mandateData;
        if (modeConfig.hasAnyTargetCheck()) {
            // TokenOut format depends on whether FIELD_TOKEN_OUT is checked
            bytes memory tokenOutData;
            if (modeConfig.hasCheckTokenOut()) {
                // Expanded: length + [token (32), amount (32)]
                tokenOutData = abi.encodePacked(
                    uint8(1), uint256(uint160(data.tokenOut)), data.tokenOutAmount
                );
            } else {
                // Pre-computed hash (32 bytes)
                bytes32 singleTokenOutHash =
                    keccak256(abi.encode(TYPEHASH_TOKEN, data.tokenOut, data.tokenOutAmount));
                bytes32 tokenOutHash = keccak256(abi.encodePacked(singleTokenOutHash));
                tokenOutData = abi.encodePacked(tokenOutHash);
            }

            // Expanded target: recipient (20) + targetChainId (32) + fillExpiry (32) + tokenOut
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

        return abi.encodePacked(header, tokenInData, mandateData);
    }

    /*//////////////////////////////////////////////////////////////
                    COMPUTE HASH (EXTERNAL FOR CALLDATA)
    //////////////////////////////////////////////////////////////*/

    /// @notice Compute hash by parsing Permit2 data
    /// @dev External function to get calldata access for EIP712TypeHashLib functions
    function computeHash(
        bytes calldata permit2Data,
        bool hasTokenInCheck,
        bool hasTargetCheck,
        bool hasTokenOutCheck
    )
        external
        view
        returns (bytes32)
    {
        // Parse header: arbiter (20) + nonce (32) + deadline (32)
        address arbiter = address(bytes20(permit2Data[0:20]));
        uint256 nonce = uint256(bytes32(permit2Data[20:52]));
        uint256 deadline = uint256(bytes32(permit2Data[52:84]));
        uint256 offset = 84;

        // Parse tokenIn
        bytes32 tokenPermissionsHash;
        if (hasTokenInCheck) {
            // Expanded: length + [token (32), amount (32)][]
            uint8 tokenInLength = uint8(permit2Data[offset]);
            offset += 1;

            uint256[2][] calldata tokenPermissions;
            assembly {
                tokenPermissions.offset := add(permit2Data.offset, offset)
                tokenPermissions.length := tokenInLength
            }
            tokenPermissionsHash = EIP712TypeHashLib.hashTokenPermissions(tokenPermissions);
            offset += uint256(tokenInLength) * 64;
        } else {
            // Fast path: pre-computed hash
            tokenPermissionsHash = bytes32(permit2Data[offset:offset + 32]);
            offset += 32;
        }

        // Parse mandate
        bytes32 mandateHash;
        if (hasTargetCheck) {
            // Parse expanded target
            address recipient = address(bytes20(permit2Data[offset:offset + 20]));
            offset += 20;
            uint256 targetChainId = uint256(bytes32(permit2Data[offset:offset + 32]));
            offset += 32;
            uint256 fillExpiry = uint256(bytes32(permit2Data[offset:offset + 32]));
            offset += 32;

            // Parse tokenOut
            bytes32 tokenOutHash;
            if (hasTokenOutCheck) {
                // Expanded: length + [token (32), amount (32)][]
                uint8 tokenOutLength = uint8(permit2Data[offset]);
                offset += 1;

                uint256[2][] calldata tokenOut;
                assembly {
                    tokenOut.offset := add(permit2Data.offset, offset)
                    tokenOut.length := tokenOutLength
                }
                tokenOutHash = EIP712TypeHashLib.hashTokenOut(tokenOut);
                offset += uint256(tokenOutLength) * 64;
            } else {
                // Pre-computed hash
                tokenOutHash = bytes32(permit2Data[offset:offset + 32]);
                offset += 32;
            }

            // Hash target
            bytes32 targetHash = EIP712TypeHashLib.hashTargetAttributesRaw(
                recipient, tokenOutHash, targetChainId, fillExpiry
            );

            // Parse mandate footer
            uint128 minGas = uint128(bytes16(permit2Data[offset:offset + 16]));
            offset += 16;
            bytes32 originOpsHash = bytes32(permit2Data[offset:offset + 32]);
            offset += 32;
            bytes32 destOpsHash = bytes32(permit2Data[offset:offset + 32]);
            offset += 32;
            bytes32 qualificationHash = bytes32(permit2Data[offset:offset + 32]);

            mandateHash = EIP712TypeHashLib.hashMandateRaw(
                targetHash, minGas, originOpsHash, destOpsHash, qualificationHash
            );
        } else {
            // Fast path: pre-computed mandateHash
            mandateHash = bytes32(permit2Data[offset:offset + 32]);
        }

        // Compute Permit2 struct hash
        bytes32 structHash = EIP712TypeHashLib.hashPermit2(
            tokenPermissionsHash, arbiter, nonce, deadline, mandateHash
        );

        // Apply Permit2 domain separator
        return _permit2HashTypedData(structHash);
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

/// @title Permit2ClaimPolicy_check1271SignedAction_Invariant_Test
/// @notice Invariant tests for Permit2ClaimPolicy.check1271SignedAction
contract Permit2ClaimPolicy_check1271SignedAction_Invariant_Test is
    StdInvariant,
    Permit2ClaimPolicy_Unit_Test
{
    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    Permit2ClaimPolicyHandler public handler;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        super.setUp();

        handler = new Permit2ClaimPolicyHandler();
        handler.setUp();

        targetContract(address(handler));
        excludeContract(address(permit2ClaimPolicy));
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
