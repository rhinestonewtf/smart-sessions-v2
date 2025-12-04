// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Contracts
import { EIP712TypeHashLib } from "@compact-utils/types/EIP712TypeHashLib.sol";

// Interfaces
import { I1271Policy } from "@smartsessions/interfaces/IPolicy.sol";
import { IArbiter } from "@policies/claim/base/interfaces/IArbiter.sol";

// Libraries
import { BaseConfigLib, PolicyConfig } from "@policies/claim/base/lib/BaseConfigLib.sol";
import { BaseStorageLib, BasePolicyStorage } from "@policies/claim/base/lib/BaseStorageLib.sol";
import { CalldataSliceLib } from "@policies/claim/base/lib/CalldataSliceLib.sol";
import { ArgPolicyTreeLibV2 } from "@policies/claim/base/lib/ArgPolicyTreeLibV2.sol";
import { EnumerableSetLib } from "solady/utils/EnumerableSetLib.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import {
    ParamRules,
    QualificationRulesStorage,
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

// forgefmt: disable-start
/// @title Base Validation Library
/// @author Rhinestone
/// @notice Shared validation logic for ClaimPolicy fields
/// @dev Contains validation functions for 8 of 9 fields (tokenIn is protocol-specific).
///      Used by both CompactClaimPolicy and Permit2ClaimPolicy.
/// ┌─────────────────────────────────────────────────────────────┐
/// │                    Validation Flow                          │
/// │                                                             │
/// │  For each field:                                            │
/// │  1. Check mode (SKIP → return true immediately)             │
/// │  2. Route to appropriate validator:                         │
/// │     - STORAGE/CATCHALL → validate against stored config     │
/// │     - SUBPOLICY → delegate to external policy contract      │
/// │  3. Return validation result                                │
/// │                                                             │
/// │  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐ │
/// │  │  MODE_SKIP   │────►│    Always    │────►│     true     │ │
/// │  └──────────────┘     │    valid     │     └──────────────┘ │
/// │                       └──────────────┘                      │
/// │                                                             │
/// │  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐ │
/// │  │   STORAGE/   │────►│    Check     │────►│  true/false  │ │
/// │  │   CATCHALL   │     │   storage    │     └──────────────┘ │
/// │  └──────────────┘     └──────────────┘                      │
/// │                                                             │
/// │  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐ │
/// │  │  SUBPOLICY   │────►│    Call      │────►│  true/false  │ │
/// │  │              │     │   external   │     └──────────────┘ │
/// │  └──────────────┘     └──────────────┘                      │
/// └─────────────────────────────────────────────────────────────┘
// forgefmt: disable-end
library BaseValidationLib {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using CalldataSliceLib for bytes;
    using BaseConfigLib for PolicyConfig;
    using BaseConfigLib for uint8;
    using ArgPolicyTreeLibV2 for ParamRules;
    using EnumerableSetLib for EnumerableSetLib.AddressSet;

    /*//////////////////////////////////////////////////////////////
                          ARBITER VALIDATION
    //////////////////////////////////////////////////////////////

    The arbiter is the entity responsible for settling claims.
    Validation ensures only authorized arbiters can process claims.

    //////////////////////////////////////////////////////////////*/

    /// @notice Validates arbiter address with mode-based routing
    /// @dev Routes to storage or sub-policy validation based on mode
    /// @param $ The storage pointer
    /// @param arbiter The arbiter address to validate
    /// @param config The policy configuration
    /// @param configId The configuration ID
    /// @param account The account being validated
    /// @param hash The hash for sub-policy validation
    /// @return True if arbiter is valid according to the configured rules
    function validateArbiter(
        BasePolicyStorage storage $,
        address arbiter,
        PolicyConfig config,
        ConfigId configId,
        address account,
        bytes32 hash
    )
        internal
        view
        returns (bool)
    {
        uint8 mode = config.getFieldMode(FIELD_ARBITER);

        // MODE_SKIP: No validation required
        if (mode == MODE_SKIP) return true;

        // STORAGE or CATCHALL: Check against stored arbiter
        if (mode.isStorageMode()) {
            return _validateArbiterStorage($, arbiter);
        }

        // SUBPOLICY: Delegate to external policy
        if (mode.isSubPolicyMode()) {
            return _validateArbiterSubPolicy($, arbiter, configId, account, hash);
        }

        // Unknown mode - fail safely
        return false;
    }

    /// @notice Validates arbiter against stored whitelist
    /// @dev Checks if arbiter is in the authorized set
    /// @param $ The storage pointer
    /// @param arbiter The arbiter address to validate
    /// @return True if arbiter is in the whitelist
    function _validateArbiterStorage(
        BasePolicyStorage storage $,
        address arbiter
    )
        private
        view
        returns (bool)
    {
        return $.arbiterConfig.contains(arbiter);
    }

    /// @notice Validates arbiter by delegating to external sub-policy
    /// @dev Encodes arbiter as signature data for the sub-policy call
    /// @param $ The storage pointer
    /// @param arbiter The arbiter address to validate
    /// @param configId The configuration ID
    /// @param account The account being validated
    /// @param hash The original hash being validated
    /// @return True if sub-policy approves the arbiter
    function _validateArbiterSubPolicy(
        BasePolicyStorage storage $,
        address arbiter,
        ConfigId configId,
        address account,
        bytes32 hash
    )
        private
        view
        returns (bool)
    {
        address policy = $.subPolicies[FIELD_ARBITER];
        bytes memory arbiterData = abi.encode(arbiter);
        return I1271Policy(policy)
            .check1271SignedAction({
                id: configId,
                requestSender: msg.sender,
                account: account,
                hash: hash,
                signature: arbiterData
            });
    }

    /*//////////////////////////////////////////////////////////////
                          EXPIRY VALIDATION
    //////////////////////////////////////////////////////////////

    Expiry validation ensures the claim/permit expires within
    acceptable bounds. This prevents:
    - Claims that expire too soon (minExpiry)
    - Claims that are valid for too long (maxExpiry)

    For Compact: This is the "claimExpires" field
    For Permit2: This is the "deadline" field

    //////////////////////////////////////////////////////////////*/

    /// @notice Validates expiry timestamp with mode-based routing
    /// @dev Checks that expiry falls within configured min/max bounds
    /// @param $ The storage pointer
    /// @param expiry The expiry timestamp to validate (claimExpires or deadline)
    /// @param config The policy configuration
    /// @param configId The configuration ID
    /// @param account The account being validated
    /// @param hash The hash for sub-policy validation
    /// @return True if expiry is within configured bounds
    function validateExpiry(
        BasePolicyStorage storage $,
        uint256 expiry,
        PolicyConfig config,
        ConfigId configId,
        address account,
        bytes32 hash
    )
        internal
        view
        returns (bool)
    {
        uint8 mode = config.getFieldMode(FIELD_EXPIRY);

        // MODE_SKIP: No validation required
        if (mode == MODE_SKIP) return true;

        // STORAGE or CATCHALL: Check against stored bounds
        if (mode.isStorageMode()) {
            return _validateExpiryStorage($, expiry);
        }

        // SUBPOLICY: Delegate to external policy
        if (mode.isSubPolicyMode()) {
            return _validateExpirySubPolicy($, expiry, configId, account, hash);
        }

        return false;
    }

    /// @notice Validates expiry against stored min/max bounds
    /// @dev Expiry must satisfy: minExpiry <= expiry <= maxExpiry
    /// @param $ The storage pointer
    /// @param expiry The expiry timestamp to validate
    /// @return True if expiry is within bounds
    function _validateExpiryStorage(
        BasePolicyStorage storage $,
        uint256 expiry
    )
        private
        view
        returns (bool)
    {
        uint256 packed = $.expiryConfig;
        (uint128 min, uint128 max) = BaseConfigLib.unpackUint128(packed);
        return expiry >= min && expiry <= max;
    }

    /// @notice Validates expiry by delegating to external sub-policy
    /// @param $ The storage pointer
    /// @param expiry The expiry timestamp to validate
    /// @param configId The configuration ID
    /// @param account The account being validated
    /// @param hash The original hash being validated
    /// @return True if sub-policy approves the expiry
    function _validateExpirySubPolicy(
        BasePolicyStorage storage $,
        uint256 expiry,
        ConfigId configId,
        address account,
        bytes32 hash
    )
        private
        view
        returns (bool)
    {
        address policy = $.subPolicies[FIELD_EXPIRY];
        bytes memory expiryData = abi.encode(expiry);
        return I1271Policy(policy)
            .check1271SignedAction({
                id: configId,
                requestSender: msg.sender,
                account: account,
                hash: hash,
                signature: expiryData
            });
    }

    /*//////////////////////////////////////////////////////////////
                            RECIPIENT VALIDATION
    //////////////////////////////////////////////////////////////

    Recipient validation ensures funds are sent to authorized
    addresses on the target chain.

    Two validation modes available:
    ┌─────────────────────────────────────────────────────────────┐
    │  FIELD_RECIPIENT (storage-based)                            │
    │  ├── Validates against stored recipient per chainId         │
    │  ├── Supports ANY_ADDRESS sentinel for wildcards            │
    │  └── Requires SLOAD for each validation                     │
    ├─────────────────────────────────────────────────────────────┤
    │  FIELD_RECIPIENT_IS_SPONSOR (flag-based)                    │
    │  ├── Enforces recipient == sponsor (the account)            │
    │  ├── No storage lookup required - just memory comparison    │
    │  └── Ideal for "bridge to self" session keys                │
    └─────────────────────────────────────────────────────────────┘

    //////////////////////////////////////////////////////////////*/

    /// @notice Validates recipient address with mode-based routing
    /// @dev Recipient validation is per-targetChainId (or catch-all with chainId=0)
    /// @param $ The storage pointer
    /// @param recipient The recipient address to validate
    /// @param targetChainId The target chain for this recipient
    /// @param config The policy configuration
    /// @param configId The configuration ID
    /// @param account The account being validated
    /// @param hash The hash for sub-policy validation
    /// @return True if recipient is authorized for the target chain
    function validateRecipient(
        BasePolicyStorage storage $,
        address recipient,
        uint256 targetChainId,
        PolicyConfig config,
        ConfigId configId,
        address account,
        bytes32 hash
    )
        internal
        view
        returns (bool)
    {
        uint8 mode = config.getFieldMode(FIELD_RECIPIENT);

        // MODE_SKIP: No validation required
        if (mode == MODE_SKIP) return true;

        // STORAGE or CATCHALL: Check against stored recipient
        if (mode.isStorageMode()) {
            return _validateRecipientStorage($, recipient, targetChainId, mode);
        }

        // SUBPOLICY: Delegate to external policy
        if (mode.isSubPolicyMode()) {
            return _validateRecipientSubPolicy($, recipient, targetChainId, configId, account, hash);
        }

        return false;
    }

    /// @notice Validates recipient against stored configuration
    /// @dev Uses effective chainId (0 for catch-all mode)
    /// @param $ The storage pointer
    /// @param recipient The recipient address to validate
    /// @param targetChainId The target chain ID
    /// @param mode The field mode (determines catch-all behavior)
    /// @return True if recipient matches stored configuration
    function _validateRecipientStorage(
        BasePolicyStorage storage $,
        address recipient,
        uint256 targetChainId,
        uint8 mode
    )
        private
        view
        returns (bool)
    {
        uint256 effectiveChainId = mode.getEffectiveChainId(targetChainId);
        address expected = $.recipientConfig[effectiveChainId];
        return recipient == expected || expected == ANY_ADDRESS;
    }

    /// @notice Validates recipient by delegating to external sub-policy
    /// @param $ The storage pointer
    /// @param recipient The recipient address to validate
    /// @param targetChainId The target chain ID
    /// @param configId The configuration ID
    /// @param account The account being validated
    /// @param hash The original hash being validated
    /// @return True if sub-policy approves the recipient
    function _validateRecipientSubPolicy(
        BasePolicyStorage storage $,
        address recipient,
        uint256 targetChainId,
        ConfigId configId,
        address account,
        bytes32 hash
    )
        private
        view
        returns (bool)
    {
        address policy = $.subPolicies[FIELD_RECIPIENT];
        bytes memory recipientData = abi.encode(targetChainId, recipient);
        return I1271Policy(policy)
            .check1271SignedAction({
                id: configId,
                requestSender: msg.sender,
                account: account,
                hash: hash,
                signature: recipientData
            });
    }

    /*//////////////////////////////////////////////////////////////
                       FILL EXPIRY VALIDATION
    //////////////////////////////////////////////////////////////

    Fill expiry defines when the claim must be filled by.
    Validation ensures fill deadlines are within acceptable bounds.

    //////////////////////////////////////////////////////////////*/

    /// @notice Validates fill expiry timestamp with mode-based routing
    /// @dev Fill expiry validation is per-targetChainId
    /// @param $ The storage pointer
    /// @param fillExpiry The fill expiry timestamp to validate
    /// @param targetChainId The target chain ID
    /// @param config The policy configuration
    /// @param configId The configuration ID
    /// @param account The account being validated
    /// @param hash The hash for sub-policy validation
    /// @return True if fill expiry is within configured bounds
    function validateFillExpiry(
        BasePolicyStorage storage $,
        uint256 fillExpiry,
        uint256 targetChainId,
        PolicyConfig config,
        ConfigId configId,
        address account,
        bytes32 hash
    )
        internal
        view
        returns (bool)
    {
        uint8 mode = config.getFieldMode(FIELD_FILL_EXPIRY);

        // MODE_SKIP: No validation required
        if (mode == MODE_SKIP) return true;

        // STORAGE or CATCHALL: Check against stored bounds
        if (mode.isStorageMode()) {
            return _validateFillExpiryStorage($, fillExpiry, targetChainId, mode);
        }

        // SUBPOLICY: Delegate to external policy
        if (mode.isSubPolicyMode()) {
            return
                _validateFillExpirySubPolicy($, fillExpiry, targetChainId, configId, account, hash);
        }

        return false;
    }

    /// @notice Validates fill expiry against stored min/max bounds
    /// @param $ The storage pointer
    /// @param fillExpiry The fill expiry timestamp to validate
    /// @param targetChainId The target chain ID
    /// @param mode The field mode
    /// @return True if fill expiry is within bounds
    function _validateFillExpiryStorage(
        BasePolicyStorage storage $,
        uint256 fillExpiry,
        uint256 targetChainId,
        uint8 mode
    )
        private
        view
        returns (bool)
    {
        uint256 effectiveChainId = mode.getEffectiveChainId(targetChainId);
        uint256 packed = $.fillExpiryConfig[effectiveChainId];
        (uint128 min, uint128 max) = BaseConfigLib.unpackUint128(packed);
        return fillExpiry >= min && fillExpiry <= max;
    }

    /// @notice Validates fill expiry by delegating to external sub-policy
    /// @param $ The storage pointer
    /// @param fillExpiry The fill expiry timestamp to validate
    /// @param targetChainId The target chain ID
    /// @param configId The configuration ID
    /// @param account The account being validated
    /// @param hash The original hash being validated
    /// @return True if sub-policy approves the fill expiry
    function _validateFillExpirySubPolicy(
        BasePolicyStorage storage $,
        uint256 fillExpiry,
        uint256 targetChainId,
        ConfigId configId,
        address account,
        bytes32 hash
    )
        private
        view
        returns (bool)
    {
        address policy = $.subPolicies[FIELD_FILL_EXPIRY];
        bytes memory fillExpiryData = abi.encode(targetChainId, fillExpiry);
        return I1271Policy(policy)
            .check1271SignedAction({
                id: configId,
                requestSender: msg.sender,
                account: account,
                hash: hash,
                signature: fillExpiryData
            });
    }

    /*//////////////////////////////////////////////////////////////
                        TOKEN OUT VALIDATION
    //////////////////////////////////////////////////////////////

    TokenOut validation ensures only whitelisted tokens can be
    received on the target chain.

    Token format in calldata:
    ┌────────────────────────────────────────────────────────┐
    │  TokenOut Array                                        │
    │  ┌────────────────────────────────────────────────┐    │
    │  │  length (uint8) - 1 byte                       │    │
    │  └────────────────────────────────────────────────┘    │
    │  ┌────────────────────────────────────────────────┐    │
    │  │  Entry (64 bytes = 2 slots):                   │    │
    │  │  ┌────────────────────┬────────────────────┐   │    │
    │  │  │ token address (32) │ amount (32)        │   │    │
    │  │  │ (left-padded)      │                    │   │    │
    │  │  └────────────────────┴────────────────────┘   │    │
    │  └────────────────────────────────────────────────┘    │
    └────────────────────────────────────────────────────────┘

    //////////////////////////////////////////////////////////////*/

    /// @notice Validates tokenOut array with mode-based routing
    /// @dev Reads token array from calldata, validates each, returns hash
    /// @param $ The storage pointer
    /// @param data The calldata containing tokenOut data
    /// @param offset Current offset in calldata
    /// @param targetChainId The target chain ID
    /// @param config The policy configuration
    /// @param configId The configuration ID
    /// @param account The account being validated
    /// @param hash The hash for sub-policy validation
    /// @return valid True if all tokens are whitelisted
    /// @return tokenOutHash The computed hash of the tokenOut array
    /// @return newOffset Updated offset after reading tokenOut data
    function validateTokenOut(
        BasePolicyStorage storage $,
        bytes calldata data,
        uint256 offset,
        uint256 targetChainId,
        PolicyConfig config,
        ConfigId configId,
        address account,
        bytes32 hash
    )
        internal
        view
        returns (bool valid, bytes32 tokenOutHash, uint256 newOffset)
    {
        uint8 mode = config.getFieldMode(FIELD_TOKEN_OUT);

        // Route to appropriate validator
        if (mode.isStorageMode()) {
            return _validateTokenOutStorage($, data, offset, targetChainId, mode);
        }

        if (mode.isSubPolicyMode()) {
            return
                _validateTokenOutSubPolicy($, data, offset, targetChainId, configId, account, hash);
        }

        // Unknown mode
        return (false, bytes32(0), 0);
    }

    /// @notice Validates tokenOut against stored whitelist
    /// @param $ The storage pointer
    /// @param data The calldata containing tokenOut data
    /// @param offset Current offset in calldata
    /// @param targetChainId The target chain ID
    /// @param mode The field mode
    /// @return valid True if all tokens are whitelisted
    /// @return tokenOutHash The computed hash
    /// @return newOffset Updated offset
    function _validateTokenOutStorage(
        BasePolicyStorage storage $,
        bytes calldata data,
        uint256 offset,
        uint256 targetChainId,
        uint8 mode
    )
        private
        view
        returns (bool valid, bytes32 tokenOutHash, uint256 newOffset)
    {
        // Slice out array length
        uint8 length;
        (length, offset) = data.sliceUint8(offset);

        // Get whitelist for this chain (or catch-all)
        uint256 effectiveChainId = mode.getEffectiveChainId(targetChainId);
        EnumerableSetLib.AddressSet storage tokenSet = $.tokenOutSet[effectiveChainId];

        // Empty whitelist = no config exists = fail
        if (tokenSet.length() == 0) {
            return (false, bytes32(0), 0);
        }

        // Create calldata pointer to token array (2 slots per entry)
        uint256[2][] calldata tokenOut;
        (tokenOut, offset) = data.sliceUint256PairArray(offset, length);

        // Validate each token against whitelist
        for (uint8 i = 0; i < length; i++) {
            address token = address(uint160(tokenOut[i][0]));
            if (!tokenSet.contains(token)) {
                return (false, bytes32(0), 0);
            }
        }

        // Compute hash for EIP-712
        tokenOutHash = EIP712TypeHashLib.hashTokenOut(tokenOut);

        return (true, tokenOutHash, offset);
    }

    /// @notice Validates tokenOut by delegating to external sub-policy
    /// @param $ The storage pointer
    /// @param data The calldata containing tokenOut data
    /// @param offset Current offset in calldata
    /// @param targetChainId The target chain ID
    /// @param configId The configuration ID
    /// @param account The account being validated
    /// @param hash The original hash
    /// @return valid True if sub-policy approves
    /// @return tokenOutHash The computed hash
    /// @return newOffset Updated offset
    function _validateTokenOutSubPolicy(
        BasePolicyStorage storage $,
        bytes calldata data,
        uint256 offset,
        uint256 targetChainId,
        ConfigId configId,
        address account,
        bytes32 hash
    )
        private
        view
        returns (bool, bytes32, uint256)
    {
        // Slice out array length
        uint8 length;
        (length, offset) = data.sliceUint8(offset);

        // Create calldata pointer to token array (2 slots per entry)
        uint256[2][] calldata tokenOut;
        (tokenOut, offset) = data.sliceUint256PairArray(offset, length);

        // Delegate to sub-policy
        address policy = $.subPolicies[FIELD_TOKEN_OUT];
        bytes memory tokenOutData = abi.encode(targetChainId, tokenOut);
        bool valid = I1271Policy(policy)
            .check1271SignedAction({
                id: configId,
                requestSender: msg.sender,
                account: account,
                hash: hash,
                signature: tokenOutData
            });

        // Early return if invalid
        if (!valid) return (false, bytes32(0), 0);

        // Compute hash for EIP-712
        bytes32 tokenOutHash = EIP712TypeHashLib.hashTokenOut(tokenOut);
        return (true, tokenOutHash, offset);
    }

    /*//////////////////////////////////////////////////////////////
                       ORIGIN OPS VALIDATION
    //////////////////////////////////////////////////////////////

    Origin operations are optional executions on the origin chain.
    This validation enforces whether origin ops are required or not.

    The opsHash is compared against NO_OPS constant:
    - opsHash == NO_OPS → No operations present
    - opsHash != NO_OPS → Operations are present

    //////////////////////////////////////////////////////////////*/

    /// @notice Validates origin operations requirement with mode-based routing
    /// @dev Checks if originOps presence matches the requirement
    /// @param $ The storage pointer
    /// @param data The calldata containing originOps hash
    /// @param offset Current offset in calldata
    /// @param chainId The origin chain ID
    /// @param config The policy configuration
    /// @param configId The configuration ID
    /// @param account The account being validated
    /// @param hash The hash for sub-policy validation
    /// @return valid True if originOps requirement is satisfied
    /// @return opsHash The originOps hash read from calldata
    /// @return newOffset Updated offset after reading
    function validateOriginOps(
        BasePolicyStorage storage $,
        bytes calldata data,
        uint256 offset,
        uint256 chainId,
        PolicyConfig config,
        ConfigId configId,
        address account,
        bytes32 hash
    )
        internal
        view
        returns (bool valid, bytes32 opsHash, uint256 newOffset)
    {
        // Slice out the ops hash
        (opsHash, offset) = data.sliceBytes32(offset);

        uint8 mode = config.getFieldMode(FIELD_ORIGIN_OPS);

        // MODE_SKIP: Always valid
        if (mode == MODE_SKIP) {
            return (true, opsHash, offset);
        }

        // Check if ops are present (hash != NO_OPS)
        bool hasOps = opsHash != Constants.NO_OPS;

        // STORAGE or CATCHALL: Compare against requirement
        if (mode.isStorageMode()) {
            bool required = _getOriginOpsRequirement($, chainId, mode);
            return (hasOps == required, opsHash, offset);
        }

        // SUBPOLICY: Delegate validation
        if (mode.isSubPolicyMode()) {
            bool result = _validateOriginOpsSubPolicy($, opsHash, chainId, configId, account, hash);
            return (result, opsHash, offset);
        }

        return (false, opsHash, offset);
    }

    /// @notice Gets origin ops requirement from storage
    /// @param $ The storage pointer
    /// @param chainId The origin chain ID
    /// @param mode The field mode
    /// @return True if origin ops are required
    function _getOriginOpsRequirement(
        BasePolicyStorage storage $,
        uint256 chainId,
        uint8 mode
    )
        private
        view
        returns (bool)
    {
        uint256 effectiveChainId = mode.getEffectiveChainId(chainId);
        return $.originOpsConfig[effectiveChainId];
    }

    /// @notice Validates origin ops by delegating to external sub-policy
    /// @param $ The storage pointer
    /// @param opsHash The origin ops hash
    /// @param chainId The origin chain ID
    /// @param configId The configuration ID
    /// @param account The account being validated
    /// @param hash The original hash
    /// @return True if sub-policy approves
    function _validateOriginOpsSubPolicy(
        BasePolicyStorage storage $,
        bytes32 opsHash,
        uint256 chainId,
        ConfigId configId,
        address account,
        bytes32 hash
    )
        private
        view
        returns (bool)
    {
        address policy = $.subPolicies[FIELD_ORIGIN_OPS];
        bytes memory opsData = abi.encode(chainId, opsHash);
        return I1271Policy(policy)
            .check1271SignedAction({
                id: configId,
                requestSender: msg.sender,
                account: account,
                hash: hash,
                signature: opsData
            });
    }

    /*//////////////////////////////////////////////////////////////
                        DEST OPS VALIDATION
    //////////////////////////////////////////////////////////////

    Destination operations are optional executions on the target chain.
    Similar to origin ops, this validates the requirement.

    //////////////////////////////////////////////////////////////*/

    /// @notice Validates destination operations requirement with mode-based routing
    /// @dev Checks if destOps presence matches the requirement
    /// @param $ The storage pointer
    /// @param data The calldata containing destOps hash
    /// @param offset Current offset in calldata
    /// @param targetChainId The target chain ID
    /// @param config The policy configuration
    /// @param configId The configuration ID
    /// @param account The account being validated
    /// @param hash The hash for sub-policy validation
    /// @return valid True if destOps requirement is satisfied
    /// @return opsHash The destOps hash read from calldata
    /// @return newOffset Updated offset after reading
    function validateDestOps(
        BasePolicyStorage storage $,
        bytes calldata data,
        uint256 offset,
        uint256 targetChainId,
        PolicyConfig config,
        ConfigId configId,
        address account,
        bytes32 hash
    )
        internal
        view
        returns (bool valid, bytes32 opsHash, uint256 newOffset)
    {
        // Slice out the ops hash
        (opsHash, offset) = data.sliceBytes32(offset);

        uint8 mode = config.getFieldMode(FIELD_DEST_OPS);

        // MODE_SKIP: Always valid
        if (mode == MODE_SKIP) {
            return (true, opsHash, offset);
        }

        // Check if ops are present
        bool hasOps = opsHash != Constants.NO_OPS;

        // STORAGE or CATCHALL: Compare against requirement
        if (mode.isStorageMode()) {
            bool required = _getDestOpsRequirement($, targetChainId, mode);
            return (hasOps == required, opsHash, offset);
        }

        // SUBPOLICY: Delegate validation
        if (mode.isSubPolicyMode()) {
            bool result =
                _validateDestOpsSubPolicy($, opsHash, targetChainId, configId, account, hash);
            return (result, opsHash, offset);
        }

        return (false, opsHash, offset);
    }

    /// @notice Gets dest ops requirement from storage
    /// @param $ The storage pointer
    /// @param targetChainId The target chain ID
    /// @param mode The field mode
    /// @return True if dest ops are required
    function _getDestOpsRequirement(
        BasePolicyStorage storage $,
        uint256 targetChainId,
        uint8 mode
    )
        private
        view
        returns (bool)
    {
        uint256 effectiveChainId = mode.getEffectiveChainId(targetChainId);
        return $.destOpsConfig[effectiveChainId];
    }

    /// @notice Validates dest ops by delegating to external sub-policy
    /// @param $ The storage pointer
    /// @param opsHash The dest ops hash
    /// @param targetChainId The target chain ID
    /// @param configId The configuration ID
    /// @param account The account being validated
    /// @param hash The original hash
    /// @return True if sub-policy approves
    function _validateDestOpsSubPolicy(
        BasePolicyStorage storage $,
        bytes32 opsHash,
        uint256 targetChainId,
        ConfigId configId,
        address account,
        bytes32 hash
    )
        private
        view
        returns (bool)
    {
        address policy = $.subPolicies[FIELD_DEST_OPS];
        bytes memory opsData = abi.encode(targetChainId, opsHash);
        return I1271Policy(policy)
            .check1271SignedAction({
                id: configId,
                requestSender: msg.sender,
                account: account,
                hash: hash,
                signature: opsData
            });
    }

    /*//////////////////////////////////////////////////////////////
                       QUALIFICATION VALIDATION
     //////////////////////////////////////////////////////////////

     Qualification is arbitrary arbiter-specific data.
     The validation:
     1. Evaluates parameter rules against qualification data
     2. Computes the qualification hash

     Qualification data format (storage mode):
     ┌────────────────────────────────────────────────────────┐
     │  [dataLength: 32][qualificationData: dataLength]       │
     └────────────────────────────────────────────────────────┘

     Qualification data format (sub-policy mode):
     ┌────────────────────────────────────────────────────────┐
     │  [flags: 1][dataLength: 32][qualificationData: length] │
     │                                                        │
     │  flags (uint8):                                        │
     │  ┌──────────────────────────────────────────┐          │
     │  │ bit 0: useArbiterHash                    │          │
     │  │   0 = use keccak256(data)                │          │
     │  │   1 = call arbiter.qualificationHash()   │          │
     │  └──────────────────────────────────────────┘          │
     └────────────────────────────────────────────────────────┘

     //////////////////////////////////////////////////////////////*/

    /// @notice Validates qualification data with mode-based routing
    /// @dev Evaluates parameter rules and computes qualification hash
    /// @param $ The storage pointer
    /// @param data The calldata containing qualification data
    /// @param offset Current offset in calldata
    /// @param chainId The chain ID for rule lookup
    /// @param arbiter The arbiter address for rule lookup
    /// @param config The policy configuration
    /// @param configId The configuration ID
    /// @param account The account being validated
    /// @param hash The hash for sub-policy validation
    /// @return valid True if qualification passes all rules
    /// @return qualificationHash The computed qualification hash
    /// @return newOffset Updated offset after reading
    function validateQualification(
        BasePolicyStorage storage $,
        bytes calldata data,
        uint256 offset,
        uint256 chainId,
        address arbiter,
        PolicyConfig config,
        ConfigId configId,
        address account,
        bytes32 hash
    )
        internal
        view
        returns (bool valid, bytes32 qualificationHash, uint256 newOffset)
    {
        uint8 mode = config.getFieldMode(FIELD_QUALIFICATION);

        // Route to appropriate validator
        if (mode.isStorageMode()) {
            return _validateQualificationStorage($, data, offset, chainId, arbiter, mode);
        }

        if (mode.isSubPolicyMode()) {
            return _validateQualificationSubPolicy(
                $, data, offset, chainId, arbiter, configId, account, hash
            );
        }

        return (false, bytes32(0), 0);
    }

    /// @notice Validates qualification using stored parameter rules
    /// @param $ The storage pointer
    /// @param data The calldata containing qualification data
    /// @param offset Current offset in calldata
    /// @param chainId The chain ID
    /// @param arbiter The arbiter address
    /// @param mode The field mode
    /// @return valid True if rules pass
    /// @return qualificationHash The computed hash
    /// @return newOffset Updated offset
    function _validateQualificationStorage(
        BasePolicyStorage storage $,
        bytes calldata data,
        uint256 offset,
        uint256 chainId,
        address arbiter,
        uint8 mode
    )
        private
        view
        returns (bool valid, bytes32 qualificationHash, uint256 newOffset)
    {
        // Slice out qualification data with length prefix
        bytes calldata qualificationData;
        (qualificationData, offset) = data.sliceBytesWithLength(offset);

        // Get config for this chain+arbiter
        uint256 effectiveChainId = mode.getEffectiveChainId(chainId);
        QualificationRulesStorage storage config = $.qualificationConfig[effectiveChainId][arbiter];

        // Evaluate parameter rules if any exist
        if (config.rules.rules.length != 0) {
            if (!config.rules.evaluateExpressionTree(qualificationData)) {
                return (false, bytes32(0), 0);
            }
        }

        // Compute hash based on stored flag
        if (config.useArbiterHash) {
            qualificationHash = IArbiter(arbiter).qualificationHash(qualificationData);
        } else {
            qualificationHash = keccak256(qualificationData);
        }

        return (true, qualificationHash, offset);
    }

    /// @notice Validates qualification by delegating to external sub-policy
    /// @dev Compared to storage based validation, this requires the data to include an extra flag
    ///      byte to determine hash method
    /// @param $ The storage pointer
    /// @param data The calldata containing qualification data
    /// @param offset Current offset in calldata
    /// @param chainId The chain ID
    /// @param arbiter The arbiter address
    /// @param configId The configuration ID
    /// @param account The account being validated
    /// @param hash The original hash
    /// @return valid True if sub-policy approves
    /// @return qualificationHash The computed hash
    /// @return newOffset Updated offset
    function _validateQualificationSubPolicy(
        BasePolicyStorage storage $,
        bytes calldata data,
        uint256 offset,
        uint256 chainId,
        address arbiter,
        ConfigId configId,
        address account,
        bytes32 hash
    )
        private
        view
        returns (bool valid, bytes32 qualificationHash, uint256 newOffset)
    {
        // Slice out flags byte first
        uint8 flags;
        (flags, offset) = data.sliceUint8(offset);

        // Slice out qualification data with length prefix
        bytes calldata qualificationData;
        (qualificationData, offset) = data.sliceBytesWithLength(offset);

        // Delegate to sub-policy
        address policy = $.subPolicies[FIELD_QUALIFICATION];
        bytes memory qualData = abi.encode(chainId, arbiter, qualificationData);
        valid = I1271Policy(policy)
            .check1271SignedAction({
                id: configId,
                requestSender: msg.sender,
                account: account,
                hash: hash,
                signature: qualData
            });

        // Early return if invalid
        if (!valid) return (false, bytes32(0), 0);

        // Compute hash based on flags
        bool useArbiterHash = (flags & 0x01) != 0;
        if (useArbiterHash) {
            qualificationHash = IArbiter(arbiter).qualificationHash(qualificationData);
        } else {
            qualificationHash = keccak256(qualificationData);
        }

        return (true, qualificationHash, offset);
    }

    /*//////////////////////////////////////////////////////////////
                         MANDATE VALIDATION
    //////////////////////////////////////////////////////////////

    The Mandate struct contains settlement parameters. This is
    shared between Compact and Permit2 protocols.

    Mandate Structure:
    ┌────────────────────────────────────────────────────────┐
    │                       Mandate                          │
    │  ┌──────────────────────────────────────────────────┐  │
    │  │  Target (variable):                              │  │
    │  │    recipient, tokenOut[], targetChain, fillExpiry│  │
    │  ├──────────────────────────────────────────────────┤  │
    │  │  minGas (uint128) - 16 bytes                     │  │
    │  ├──────────────────────────────────────────────────┤  │
    │  │  originOpsHash (bytes32) - 32 bytes              │  │
    │  ├──────────────────────────────────────────────────┤  │
    │  │  destOpsHash (bytes32) - 32 bytes                │  │
    │  ├──────────────────────────────────────────────────┤  │
    │  │  qualificationHash (bytes32) - 32 bytes          │  │
    │  └──────────────────────────────────────────────────┘  │
    └────────────────────────────────────────────────────────┘

    //////////////////////////////////////////////////////////////*/

    /// @notice Validates the Mandate struct and computes its hash
    /// @dev Validates all nested fields (target, ops, qualification)
    /// @param $ The storage pointer
    /// @param data The calldata containing Mandate data
    /// @param offset Current offset in calldata
    /// @param chainId The origin chain ID (for ops validation)
    /// @param arbiter The arbiter address (for qualification)
    /// @param config The policy configuration
    /// @param configId The configuration ID
    /// @param account The account being validated
    /// @param hash The hash for sub-policy validation
    /// @return valid True if all Mandate fields are valid
    /// @return mandateHash The computed Mandate hash
    function validateMandate(
        BasePolicyStorage storage $,
        bytes calldata data,
        uint256 offset,
        uint256 chainId,
        address arbiter,
        PolicyConfig config,
        ConfigId configId,
        address account,
        bytes32 hash
    )
        internal
        view
        returns (bool valid, bytes32 mandateHash)
    {
        // Fast path: if no mandate-level checks are enabled, just read pre-computed hash
        if (!config.hasAnyMandateCheck()) {
            mandateHash = bytes32(data[offset:offset + 32]);
            return (true, mandateHash);
        }

        // Initialize variables
        bytes32 targetHash;
        uint256 targetChainId;

        // Validate Target if any target-related checks are enabled
        if (config.hasAnyTargetCheck()) {
            bool targetValid;
            (targetValid, targetHash, targetChainId, offset) =
                validateTarget($, data, offset, config, configId, account, hash);
            if (!targetValid) {
                return (false, bytes32(0));
            }
        } else {
            // Read pre-computed targetHash and targetChainId
            targetHash = bytes32(data[offset:offset + 32]);
            offset += 32;
            targetChainId = uint256(bytes32(data[offset:offset + 32]));
            offset += 32;
        }

        // Read minGas (not validated, just for hash computation)
        uint128 minGas = uint128(bytes16(data[offset:offset + 16]));
        offset += 16;
        // We're not using CalldataSlice lib to avoid stack too deep :)

        // Validate originOps
        bytes32 originOpsHash;
        if (config.hasCheckOriginOps()) {
            bool opsValid;
            (opsValid, originOpsHash, offset) =
                validateOriginOps($, data, offset, chainId, config, configId, account, hash);
            if (!opsValid) {
                return (false, bytes32(0));
            }
        } else {
            originOpsHash = bytes32(data[offset:offset + 32]);
            offset += 32;
        }

        // Validate destOps
        bytes32 destOpsHash;
        if (config.hasCheckDestOps()) {
            bool opsValid;
            (opsValid, destOpsHash, offset) =
                validateDestOps($, data, offset, targetChainId, config, configId, account, hash);
            if (!opsValid) {
                return (false, bytes32(0));
            }
        } else {
            destOpsHash = bytes32(data[offset:offset + 32]);
            offset += 32;
        }

        // Validate qualification
        bytes32 qualificationHash;
        if (config.hasCheckQualification()) {
            bool qualValid;
            (qualValid, qualificationHash, offset) = validateQualification(
                $, data, offset, chainId, arbiter, config, configId, account, hash
            );
            if (!qualValid) {
                return (false, bytes32(0));
            }
        } else {
            qualificationHash = bytes32(data[offset:offset + 32]);
            offset += 32;
        }

        // Compute Mandate struct hash
        mandateHash = EIP712TypeHashLib.hashMandateRaw(
            targetHash, minGas, originOpsHash, destOpsHash, qualificationHash
        );

        return (true, mandateHash);
    }

    /*//////////////////////////////////////////////////////////////
                         TARGET VALIDATION
    //////////////////////////////////////////////////////////////

    The Target struct defines settlement parameters for the target chain.

    Target Structure:
    ┌────────────────────────────────────────────────────────┐
    │                        Target                          │
    │  ┌──────────────────────────────────────────────────┐  │
    │  │  recipient (address) - 20 bytes                  │  │
    │  ├──────────────────────────────────────────────────┤  │
    │  │  targetChainId (uint256) - 32 bytes              │  │
    │  ├──────────────────────────────────────────────────┤  │
    │  │  fillExpiry (uint256) - 32 bytes                 │  │
    │  ├──────────────────────────────────────────────────┤  │
    │  │  tokenOut[] (variable)                           │  │
    │  └──────────────────────────────────────────────────┘  │
    └────────────────────────────────────────────────────────┘

    //////////////////////////////////////////////////////////////*/

    /// @notice Validates the Target struct and computes its hash
    /// @dev Validates recipient, fillExpiry, and tokenOut array
    /// @param $ The storage pointer
    /// @param data The calldata containing Target data
    /// @param offset Current offset in calldata
    /// @param config The policy configuration
    /// @param configId The configuration ID
    /// @param account The account being validated
    /// @param hash The hash for sub-policy validation
    /// @return valid True if all Target fields are valid
    /// @return targetHash The computed Target hash
    /// @return targetChainId The target chain ID (for downstream use)
    /// @return newOffset Updated offset after reading
    function validateTarget(
        BasePolicyStorage storage $,
        bytes calldata data,
        uint256 offset,
        PolicyConfig config,
        ConfigId configId,
        address account,
        bytes32 hash
    )
        internal
        view
        returns (bool valid, bytes32 targetHash, uint256 targetChainId, uint256 newOffset)
    {
        // Decode Target header
        address recipient = address(bytes20(data[offset:offset + 20]));
        targetChainId = uint256(bytes32(data[offset + 20:offset + 52]));
        uint256 fillExpiry = uint256(bytes32(data[offset + 52:offset + 84]));
        offset += 84;
        // We're not using CalldataSlice lib to avoid stack too deep :)

        // Validate recipient if required
        if (config.hasCheckRecipientIsSponsor()) {
            // Fast path: recipient must equal sponsor (no storage lookup)
            if (recipient != account) {
                return (false, bytes32(0), 0, 0);
            }
        } else if (config.hasCheckRecipient()) {
            // Storage path: validate against stored config
            if (!validateRecipient($, recipient, targetChainId, config, configId, account, hash)) {
                return (false, bytes32(0), 0, 0);
            }
        }

        // Validate fillExpiry if required
        if (config.hasCheckFillExpiry()) {
            if (!validateFillExpiry($, fillExpiry, targetChainId, config, configId, account, hash))
            {
                return (false, bytes32(0), 0, 0);
            }
        }

        // Validate tokenOut if enabled
        bytes32 tokenOutHash;
        if (config.hasCheckTokenOut()) {
            bool tokenOutValid;
            (tokenOutValid, tokenOutHash, offset) =
                validateTokenOut($, data, offset, targetChainId, config, configId, account, hash);
            if (!tokenOutValid) {
                return (false, bytes32(0), 0, 0);
            }
        } else {
            tokenOutHash = bytes32(data[offset:offset + 32]);
            offset += 32;
        }

        // Compute Target struct hash
        targetHash = EIP712TypeHashLib.hashTargetAttributesRaw(
            recipient, tokenOutHash, targetChainId, fillExpiry
        );

        return (true, targetHash, targetChainId, offset);
    }
}
