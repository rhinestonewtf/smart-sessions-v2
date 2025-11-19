// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Contracts
import { EIP712TypeHashLib } from "@compact-utils/types/EIP712TypeHashLib.sol";

// Interfaces
import { I1271Policy } from "@smartsessions/interfaces/IPolicy.sol";
import { IArbiter } from "@policies/compact/interfaces/IArbiter.sol";

// Libraries
import { ConfigLib, PolicyConfig } from "@policies/compact/lib/ConfigLib.sol";
import { StorageLib, PolicyStorage } from "@policies/compact/lib/StorageLib.sol";
import { ArgPolicyTreeLibV2 } from "@policies/compact/lib/ArgPolicyTreeLibV2.sol";
import { DomainLib } from "@the-compact/lib/DomainLib.sol";
import { EfficientHashLib } from "@solady/utils/EfficientHashLib.sol";
import { IdLib } from "@the-compact/lib/IdLib.sol";
import { EnumerableSetLib } from "solady/utils/EnumerableSetLib.sol";
import { ConfigLib as CompactPolicyConfigLib } from "@policies/compact/lib/ConfigLib.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import { ParamRules } from "@policies/compact/types/DataTypes.sol";
import {
    MODE_SKIP,
    MODE_CHECK_STORAGE,
    MODE_CHECK_CATCHALL,
    MODE_CHECK_SUBPOLICY,
    FIELD_ARBITER,
    FIELD_CLAIM_EXPIRES,
    FIELD_TOKEN_IN,
    FIELD_RECIPIENT,
    FIELD_FILL_EXPIRY,
    FIELD_TOKEN_OUT,
    FIELD_ORIGIN_OPS,
    FIELD_DEST_OPS,
    FIELD_QUALIFICATION
} from "@policies/compact/types/DataTypes.sol";
import { Constants } from "@compact-utils/types/Constants.sol";

/// @title Decode Library
/// @notice Library for extracting and validating MultiChainCompact data with mode-based validation
library DecodeLib {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using ConfigLib for PolicyConfig;
    using ConfigLib for bytes;
    using CompactPolicyConfigLib for uint8;
    using ArgPolicyTreeLibV2 for ParamRules;
    using DomainLib for bytes32;
    using EfficientHashLib for bytes32;
    using EfficientHashLib for bytes32[];
    using IdLib for uint256;
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;
    using EnumerableSetLib for EnumerableSetLib.AddressSet;

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error SubPolicyNotImplemented();

    /*//////////////////////////////////////////////////////////////
                                EXTRACT
    //////////////////////////////////////////////////////////////*/

    /// @notice Extracts and validates the MultiChainCompact data from the signature
    /// @param signature The signature containing the MultiChainCompact data used to reconstruct the
    /// hash and validate against the policy config
    /// @param config The policy configuration bitmap
    /// @param configId The configuration ID for the policy
    /// @param account The account for which the policy is being validated
    /// @param hash The original hash to validate against
    function extractAndValidate(
        bytes calldata signature,
        PolicyConfig config,
        ConfigId configId,
        address account,
        bytes32 hash
    )
        internal
        view
        returns (bool valid, bytes32 compactHash)
    {
        return _decodeAndValidate(signature, config, configId, account, hash);
    }

    /*//////////////////////////////////////////////////////////////
                                 DECODE
    //////////////////////////////////////////////////////////////*/

    /// @notice Decodes the MultiChainCompact data and validates it against the policy config
    function _decodeAndValidate(
        bytes calldata data,
        PolicyConfig config,
        ConfigId configId,
        address account,
        bytes32 hash
    )
        private
        view
        returns (bool valid, bytes32 digest)
    {
        // Decode fixed header
        bytes32 domainSeparator = bytes32(data[0:32]);
        uint256 nonce = uint256(bytes32(data[32:64]));
        uint256 expires = uint256(bytes32(data[64:96]));

        // Validate claim expires
        if (!_validateClaimExpires(expires, config, configId, account, hash)) {
            return (false, bytes32(0));
        }

        // Decode otherElements first (always at offset 96)
        (bytes32[] memory otherElements, uint256 notarizedElementOffset) =
            _decodeOtherElements(data, 96);

        // Decode and validate notarized element
        (bool elementValid, bytes32 elementHash) =
            _validateNotarizedElement(data, notarizedElementOffset, config, configId, account, hash);

        // Early return if notarized element is invalid
        if (!elementValid) {
            return (false, bytes32(0));
        }

        // Build allElements array
        uint256 totalLength = otherElements.length + 1;
        bytes32[] memory allElements = EfficientHashLib.malloc(totalLength);

        // Set the notarized element first
        allElements.set(0, elementHash);

        // Copy other elements
        for (uint256 i; i < otherElements.length; ++i) {
            allElements.set(i + 1, otherElements[i]);
        }

        // Hash all elements
        bytes32 allElementsHash = allElements.hash();

        // Hash the MultichainCompact struct
        bytes32 compactHash =
            EIP712TypeHashLib.hashCompact(account, nonce, expires, allElementsHash);

        // Calculate the digest
        digest = compactHash.withDomain(domainSeparator);

        return (true, digest);
    }

    /// @notice Validates the Element struct and returns its hash
    function _validateNotarizedElement(
        bytes calldata data,
        uint256 offset,
        PolicyConfig config,
        ConfigId configId,
        address account,
        bytes32 hash
    )
        private
        view
        returns (bool valid, bytes32 elementHash)
    {
        // Decode element header
        address arbiter = address(bytes20(data[offset:offset + 20]));
        uint256 chainId = uint256(bytes32(data[offset + 32:offset + 64]));
        offset += 64;

        // Validate arbiter
        if (!_validateArbiter(arbiter, config, configId, account, hash)) {
            return (false, bytes32(0));
        }

        // Init commitmentsHash
        bytes32 commitmentsHash;

        // Validate tokenIn if enabled
        if (config.hasCheckTokenIn()) {
            bool tokenInValid;
            (tokenInValid, commitmentsHash, offset) =
                _validateTokenIn(data, offset, chainId, config, configId, account, hash);
            if (!tokenInValid) {
                return (false, bytes32(0));
            }
        } else {
            commitmentsHash = bytes32(data[offset:offset + 32]);
            offset += 32;
        }

        // Validate mandate and get mandateHash
        (bool mandateValid, bytes32 mandateHash) =
            _validateMandate(data, offset, chainId, config, configId, account, hash, arbiter);
        if (!mandateValid) {
            return (false, bytes32(0));
        }

        // Calculate Element struct hash
        elementHash =
            EIP712TypeHashLib.hashElementRaw(arbiter, chainId, commitmentsHash, mandateHash);

        return (true, elementHash);
    }

    /// @notice Validates the Mandate struct and returns its hash
    function _validateMandate(
        bytes calldata data,
        uint256 offset,
        uint256 chainId,
        PolicyConfig config,
        ConfigId configId,
        address account,
        bytes32 hash,
        address arbiter
    )
        private
        view
        returns (bool valid, bytes32 mandateHash)
    {
        // Init targetHash and targetChainId
        bytes32 targetHash;
        uint256 targetChainId;

        // Validate target if any target-related checks are enabled
        if (config.hasCheckRecipient() || config.hasCheckFillExpiry() || config.hasCheckTokenOut())
        {
            bool targetValid;
            (targetValid, targetHash, targetChainId, offset) =
                _validateTarget(data, offset, config, configId, account, hash);
            if (!targetValid) {
                return (false, bytes32(0));
            }
        } else {
            // Read targetHash and targetChainId directly
            targetHash = bytes32(data[offset:offset + 32]);
            offset += 32;
            // Need to read targetChainId for destOps validation
            targetChainId = uint256(bytes32(data[offset:offset + 32]));
            offset += 32;
        }

        // Read minGas (not validated, just read for hash calculation)
        uint128 minGas = uint128(bytes16(data[offset:offset + 16]));
        offset += 16;

        // Validate originOps
        bytes32 originOpsHash;
        if (config.hasCheckOriginOps()) {
            bool opsValid;
            (opsValid, originOpsHash, offset) =
                _validateOriginOps(data, offset, chainId, config, configId, account, hash);
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
                _validateDestOps(data, offset, targetChainId, config, configId, account, hash);
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
            (qualValid, qualificationHash, offset) = _validateQualification(
                data, offset, chainId, arbiter, config, configId, account, hash
            );
            if (!qualValid) {
                return (false, bytes32(0));
            }
        } else {
            qualificationHash = bytes32(data[offset:offset + 32]);
            offset += 32;
        }

        // Calculate Mandate struct hash
        mandateHash = EIP712TypeHashLib.hashMandateRaw(
            targetHash, minGas, originOpsHash, destOpsHash, qualificationHash
        );

        return (true, mandateHash);
    }

    /// @notice Validates the Target struct and returns its hash and targetChainId
    function _validateTarget(
        bytes calldata data,
        uint256 offset,
        PolicyConfig config,
        ConfigId configId,
        address account,
        bytes32 hash
    )
        private
        view
        returns (bool valid, bytes32 targetHash, uint256 targetChainId, uint256 newOffset)
    {
        // Decode target header
        address recipient = address(bytes20(data[offset:offset + 20]));
        targetChainId = uint256(bytes32(data[offset + 32:offset + 64]));
        uint256 fillExpiry = uint256(bytes32(data[offset + 64:offset + 96]));
        offset += 96;

        // Validate recipient if required
        if (config.hasCheckRecipient()) {
            if (!_validateRecipient(recipient, targetChainId, config, configId, account, hash)) {
                return (false, bytes32(0), 0, 0);
            }
        }

        // Validate fillExpiry if required
        if (config.hasCheckFillExpiry()) {
            if (!_validateFillExpiry(fillExpiry, targetChainId, config, configId, account, hash)) {
                return (false, bytes32(0), 0, 0);
            }
        }

        // Init tokenOutHash
        bytes32 tokenOutHash;

        // Validate tokenOut if enabled
        if (config.hasCheckTokenOut()) {
            bool tokenOutValid;
            (tokenOutValid, tokenOutHash, offset) =
                _validateTokenOut(data, offset, targetChainId, config, configId, account, hash);
            if (!tokenOutValid) {
                return (false, bytes32(0), 0, 0);
            }
        } else {
            tokenOutHash = bytes32(data[offset:offset + 32]);
            offset += 32;
        }

        // Calculate Target struct hash
        targetHash = EIP712TypeHashLib.hashTargetAttributesRaw(
            recipient, tokenOutHash, targetChainId, fillExpiry
        );
        return (true, targetHash, targetChainId, offset);
    }

    /// @notice Decodes the other (non-notarized) elements from the MultiChainCompact data
    function _decodeOtherElements(
        bytes calldata data,
        uint256 offset
    )
        private
        pure
        returns (bytes32[] memory, uint256 newOffset)
    {
        // Decode the length of the other elements
        uint256 length = uint256(bytes32(data[offset:offset + 32]));
        offset += 32;

        // Initialize the array to hold the other elements
        bytes32[] memory elements = new bytes32[](length);

        // Parse each element
        for (uint256 i = 0; i < length; i++) {
            elements[i] = bytes32(data[offset:offset + 32]);
            offset += 32;
        }

        return (elements, offset);
    }

    /*//////////////////////////////////////////////////////////////
                                ARBITER
    //////////////////////////////////////////////////////////////*/

    /// @notice Validates arbiter with mode-based routing
    function _validateArbiter(
        address arbiter,
        PolicyConfig config,
        ConfigId configId,
        address account,
        bytes32 hash
    )
        private
        view
        returns (bool)
    {
        //  Get mode for arbiter field
        uint8 mode = config.getFieldMode(FIELD_ARBITER);

        // If mode is skip, always valid
        if (mode == MODE_SKIP) return true;

        // If mode is storage, validate from storage
        if (mode.isStorageMode()) {
            return _validateArbiterStorage(arbiter, configId, account);
        }

        // If mode is sub-policy, validate from sub-policy
        if (mode.isSubPolicyMode()) {
            return _validateArbiterSubPolicy(arbiter, configId, account, hash);
        }

        // Return false if no mode matched
        return false;
    }

    /// @notice Validates arbiter using storage
    function _validateArbiterStorage(
        address arbiter,
        ConfigId configId,
        address account
    )
        private
        view
        returns (bool)
    {
        PolicyStorage storage $ = StorageLib.getPolicyStorage();
        address expected = $.arbiterConfig[configId][msg.sender][account];
        return arbiter == expected;
    }

    /// @notice Validates arbiter using sub-policy
    function _validateArbiterSubPolicy(
        address arbiter,
        ConfigId configId,
        address account,
        bytes32 hash
    )
        private
        view
        returns (bool)
    {
        PolicyStorage storage $ = StorageLib.getPolicyStorage();
        address policy = $.subPolicies[configId][msg.sender][account][FIELD_ARBITER];

        // Encode the arbiter as the signature data
        bytes memory arbiterData = abi.encode(arbiter);

        // Call the sub-policy with the full hash and arbiter data
        return
            I1271Policy(policy)
                .check1271SignedAction(configId, msg.sender, account, hash, arbiterData);
    }

    /*//////////////////////////////////////////////////////////////
                             CLAIM EXPIRES
    //////////////////////////////////////////////////////////////*/

    /// @notice Validates claim expires with mode-based routing
    function _validateClaimExpires(
        uint256 expires,
        PolicyConfig config,
        ConfigId configId,
        address account,
        bytes32 hash
    )
        private
        view
        returns (bool)
    {
        // Get mode for claimExpires field
        uint8 mode = config.getFieldMode(FIELD_CLAIM_EXPIRES);

        // If mode is skip, always valid
        if (mode == MODE_SKIP) return true;

        // If mode is storage, validate from storage
        if (mode.isStorageMode()) {
            return _validateClaimExpiresStorage(expires, configId, account);
        }

        // If mode is sub-policy, validate from sub-policy
        if (mode.isSubPolicyMode()) {
            return _validateClaimExpiresSubPolicy(expires, configId, account, hash);
        }

        // Return false if no mode matched
        return false;
    }

    /// @notice Validates claim expires using storage
    function _validateClaimExpiresStorage(
        uint256 expires,
        ConfigId configId,
        address account
    )
        private
        view
        returns (bool)
    {
        PolicyStorage storage $ = StorageLib.getPolicyStorage();
        uint256 packed = $.claimExpiresConfig[configId][msg.sender][account];
        (uint128 min, uint128 max) = ConfigLib.unpackUint128(packed);
        return expires >= min && expires <= max;
    }

    /// @notice Validates claim expires using sub-policy
    function _validateClaimExpiresSubPolicy(
        uint256 expires,
        ConfigId configId,
        address account,
        bytes32 hash
    )
        private
        view
        returns (bool)
    {
        PolicyStorage storage $ = StorageLib.getPolicyStorage();
        address policy = $.subPolicies[configId][msg.sender][account][FIELD_CLAIM_EXPIRES];

        // Encode the expires as the signature data
        bytes memory expiresData = abi.encode(expires);

        // Call the sub-policy
        return
            I1271Policy(policy)
                .check1271SignedAction(configId, msg.sender, account, hash, expiresData);
    }

    /*//////////////////////////////////////////////////////////////
                                TOKEN IN
    //////////////////////////////////////////////////////////////*/

    /// @notice Validates tokenIn with mode-based routing
    function _validateTokenIn(
        bytes calldata data,
        uint256 offset,
        uint256 chainId,
        PolicyConfig config,
        ConfigId configId,
        address account,
        bytes32 hash
    )
        private
        view
        returns (bool valid, bytes32 commitmentsHash, uint256 newOffset)
    {
        // Get mode for tokenIn field
        uint8 mode = config.getFieldMode(FIELD_TOKEN_IN);

        // If mode is storage or catch-all, validate from storage
        if (mode.isStorageMode()) {
            return _validateTokenInStorage(data, offset, chainId, mode, configId, account);
        }

        // If mode is sub-policy, validate from sub-policy
        if (mode.isSubPolicyMode()) {
            return _validateTokenInSubPolicy(data, offset, chainId, configId, account, hash);
        }

        // Return false if no mode matched
        return (false, bytes32(0), 0);
    }

    /// @notice Validates tokenIn using storage (with optional catch-all)
    function _validateTokenInStorage(
        bytes calldata data,
        uint256 offset,
        uint256 chainId,
        uint8 mode,
        ConfigId configId,
        address account
    )
        private
        view
        returns (bool valid, bytes32 commitmentsHash, uint256 newOffset)
    {
        // Decode tokenIn length
        uint256 length = uint256(bytes32(data[offset:offset + 32]));
        offset += 32;

        // Get storage pointer
        PolicyStorage storage $ = StorageLib.getPolicyStorage();

        // Get the tokenIn set (with catch-all if mode == MODE_CHECK_CATCHALL)
        EnumerableSetLib.Bytes32Set storage tokenSet =
            $.tokenInSet[configId][msg.sender][account][mode.getEffectiveChainId(chainId)];

        // If empty, no config exists
        if (tokenSet.length() == 0) {
            return (false, bytes32(0), 0);
        }

        // Create calldata pointer to the tokenIn array data
        uint256[2][] calldata tokenIn;
        assembly {
            tokenIn.offset := add(data.offset, offset)
            tokenIn.length := length
        }

        // Validate each entry
        for (uint256 i = 0; i < length; i++) {
            bytes32 packed = ConfigLib.packTokenIn(
                address(uint160(tokenIn[i][0])), bytes12(bytes32(tokenIn[i][0]))
            );

            if (!tokenSet.contains(packed)) {
                return (false, bytes32(0), 0);
            }
        }

        // Calculate hash
        commitmentsHash = EIP712TypeHashLib.hashTokenIn(tokenIn);

        return (true, commitmentsHash, offset + (length * 64));
    }

    /// @notice Validates tokenIn using sub-policy
    function _validateTokenInSubPolicy(
        bytes calldata data,
        uint256 offset,
        uint256 chainId,
        ConfigId configId,
        address account,
        bytes32 hash
    )
        private
        view
        returns (bool, bytes32, uint256)
    {
        // Decode tokenIn length
        uint256 length = uint256(bytes32(data[offset:offset + 32]));
        offset += 32;

        // Create calldata pointer to the tokenIn array data
        uint256[2][] calldata tokenIn;
        assembly {
            tokenIn.offset := add(data.offset, offset)
            tokenIn.length := length
        }

        PolicyStorage storage $ = StorageLib.getPolicyStorage();
        address policy = $.subPolicies[configId][msg.sender][account][FIELD_TOKEN_IN];

        // Encode tokenIn and chainId as the signature data
        bytes memory tokenInData = abi.encode(chainId, tokenIn);

        // Call the sub-policy
        bool valid = I1271Policy(policy)
            .check1271SignedAction(configId, msg.sender, account, hash, tokenInData);

        // Early return if invalid
        if (!valid) return (false, bytes32(0), 0);

        // Calculate hash for return
        bytes32 commitmentsHash = EIP712TypeHashLib.hashTokenIn(tokenIn);
        return (true, commitmentsHash, offset + (length * 64));
    }

    /*//////////////////////////////////////////////////////////////
                               RECIPIENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Validates recipient with mode-based routing
    function _validateRecipient(
        address recipient,
        uint256 targetChainId,
        PolicyConfig config,
        ConfigId configId,
        address account,
        bytes32 hash
    )
        private
        view
        returns (bool)
    {
        // Get mode for recipient field
        uint8 mode = config.getFieldMode(FIELD_RECIPIENT);

        // If mode is skip, always valid
        if (mode == MODE_SKIP) return true;

        // If mode is storage or catch-all, validate from storage
        if (mode.isStorageMode()) {
            return _validateRecipientStorage(recipient, targetChainId, mode, configId, account);
        }

        // If mode is sub-policy, validate from sub-policy
        if (mode.isSubPolicyMode()) {
            return _validateRecipientSubPolicy(recipient, targetChainId, configId, account, hash);
        }

        // Return false if no mode matched
        return false;
    }

    /// @notice Validates recipient using storage (with optional catch-all)
    function _validateRecipientStorage(
        address recipient,
        uint256 targetChainId,
        uint8 mode,
        ConfigId configId,
        address account
    )
        private
        view
        returns (bool)
    {
        PolicyStorage storage $ = StorageLib.getPolicyStorage();

        // Get expected recipient from storage (with catch-all if mode == MODE_CHECK_CATCHALL)
        address expected = $.recipientConfig[
            configId
        ][msg.sender][account][mode.getEffectiveChainId(targetChainId)];

        return recipient == expected;
    }

    /// @notice Validates recipient using sub-policy
    function _validateRecipientSubPolicy(
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
        PolicyStorage storage $ = StorageLib.getPolicyStorage();
        address policy = $.subPolicies[configId][msg.sender][account][FIELD_RECIPIENT];

        // Encode recipient and targetChainId as the signature data
        bytes memory recipientData = abi.encode(targetChainId, recipient);

        // Call the sub-policy
        return I1271Policy(policy)
            .check1271SignedAction(configId, msg.sender, account, hash, recipientData);
    }

    /*//////////////////////////////////////////////////////////////
                              FILL EXPIRY
    //////////////////////////////////////////////////////////////*/

    /// @notice Validates fillExpiry with mode-based routing
    function _validateFillExpiry(
        uint256 fillExpiry,
        uint256 targetChainId,
        PolicyConfig config,
        ConfigId configId,
        address account,
        bytes32 hash
    )
        private
        view
        returns (bool)
    {
        // Get mode for fillExpiry field
        uint8 mode = config.getFieldMode(FIELD_FILL_EXPIRY);

        // If mode is skip, always valid
        if (mode == MODE_SKIP) return true;

        // If mode is storage or catch-all, validate from storage
        if (mode.isStorageMode()) {
            return _validateFillExpiryStorage(fillExpiry, targetChainId, mode, configId, account);
        }

        // If mode is sub-policy, validate from sub-policy
        if (mode.isSubPolicyMode()) {
            return _validateFillExpirySubPolicy(fillExpiry, targetChainId, configId, account, hash);
        }

        // Return false if no mode matched
        return false;
    }

    /// @notice Validates fillExpiry using storage (with optional catch-all)
    function _validateFillExpiryStorage(
        uint256 fillExpiry,
        uint256 targetChainId,
        uint8 mode,
        ConfigId configId,
        address account
    )
        private
        view
        returns (bool)
    {
        PolicyStorage storage $ = StorageLib.getPolicyStorage();

        // Get expected min/max from storage (with catch-all if mode == MODE_CHECK_CATCHALL)
        uint256 packed = $.fillExpiryConfig[
            configId
        ][msg.sender][account][mode.getEffectiveChainId(targetChainId)];

        (uint128 min, uint128 max) = ConfigLib.unpackUint128(packed);
        return fillExpiry >= min && fillExpiry <= max;
    }

    /// @notice Validates fillExpiry using sub-policy
    function _validateFillExpirySubPolicy(
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
        PolicyStorage storage $ = StorageLib.getPolicyStorage();
        address policy = $.subPolicies[configId][msg.sender][account][FIELD_FILL_EXPIRY];

        // Encode fillExpiry and targetChainId as the signature data
        bytes memory fillExpiryData = abi.encode(targetChainId, fillExpiry);

        // Call the sub-policy
        return I1271Policy(policy)
            .check1271SignedAction(configId, msg.sender, account, hash, fillExpiryData);
    }

    /*//////////////////////////////////////////////////////////////
                               TOKEN OUT
    //////////////////////////////////////////////////////////////*/

    /// @notice Validates tokenOut with mode-based routing
    function _validateTokenOut(
        bytes calldata data,
        uint256 offset,
        uint256 targetChainId,
        PolicyConfig config,
        ConfigId configId,
        address account,
        bytes32 hash
    )
        private
        view
        returns (bool valid, bytes32 tokenOutHash, uint256 newOffset)
    {
        // Get mode for tokenOut field
        uint8 mode = config.getFieldMode(FIELD_TOKEN_OUT);

        // If mode is check storage or catch-all, validate from storage
        if (mode.isStorageMode()) {
            return _validateTokenOutStorage(data, offset, targetChainId, mode, configId, account);
        }

        // If mode is sub-policy, validate from sub-policy
        if (mode.isSubPolicyMode()) {
            return _validateTokenOutSubPolicy(data, offset, targetChainId, configId, account, hash);
        }

        // Return false if no mode matched
        return (false, bytes32(0), 0);
    }

    /// @notice Validates tokenOut using storage (with optional catch-all)
    function _validateTokenOutStorage(
        bytes calldata data,
        uint256 offset,
        uint256 targetChainId,
        uint8 mode,
        ConfigId configId,
        address account
    )
        private
        view
        returns (bool valid, bytes32 tokenOutHash, uint256 newOffset)
    {
        // Decode tokenOut length
        uint256 length = uint256(bytes32(data[offset:offset + 32]));
        offset += 32;

        // Get storage pointer
        PolicyStorage storage $ = StorageLib.getPolicyStorage();

        // Get the tokenOut set (with catch-all if mode == MODE_CHECK_CATCHALL)
        EnumerableSetLib.AddressSet storage tokenSet =
            $.tokenOutSet[configId][msg.sender][account][mode.getEffectiveChainId(targetChainId)];

        // If still empty, no config exists
        if (tokenSet.length() == 0) {
            return (false, bytes32(0), 0);
        }

        // Create calldata pointer to the tokenOut array data
        uint256[2][] calldata tokenOut;
        assembly {
            tokenOut.offset := add(data.offset, offset)
            tokenOut.length := length
        }

        // Validate each entry
        for (uint256 i = 0; i < length; i++) {
            address token = address(uint160(tokenOut[i][0]));

            if (!tokenSet.contains(token)) {
                return (false, bytes32(0), 0);
            }
        }

        // Calculate hash
        tokenOutHash = EIP712TypeHashLib.hashTokenOut(tokenOut);

        return (true, tokenOutHash, offset + (length * 64));
    }

    /// @notice Validates tokenOut using sub-policy
    function _validateTokenOutSubPolicy(
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
        // Decode tokenOut length
        uint256 length = uint256(bytes32(data[offset:offset + 32]));
        offset += 32;

        // Create calldata pointer to the tokenOut array data
        uint256[2][] calldata tokenOut;
        assembly {
            tokenOut.offset := add(data.offset, offset)
            tokenOut.length := length
        }

        PolicyStorage storage $ = StorageLib.getPolicyStorage();
        address policy = $.subPolicies[configId][msg.sender][account][FIELD_TOKEN_OUT];

        // Encode tokenOut and targetChainId as the signature data
        bytes memory tokenOutData = abi.encode(targetChainId, tokenOut);

        // Call the sub-policy
        bool valid = I1271Policy(policy)
            .check1271SignedAction(configId, msg.sender, account, hash, tokenOutData);

        if (!valid) return (false, bytes32(0), 0);

        // Calculate hash for return
        bytes32 tokenOutHash = EIP712TypeHashLib.hashTokenOut(tokenOut);
        return (true, tokenOutHash, offset + (length * 64));
    }

    /*//////////////////////////////////////////////////////////////
                               ORIGIN OPS
    //////////////////////////////////////////////////////////////*/

    /// @notice Validates originOps with mode-based routing
    function _validateOriginOps(
        bytes calldata data,
        uint256 offset,
        uint256 chainId,
        PolicyConfig config,
        ConfigId configId,
        address account,
        bytes32 hash
    )
        private
        view
        returns (bool valid, bytes32 opsHash, uint256 newOffset)
    {
        // Read the ops hash
        opsHash = bytes32(data[offset:offset + 32]);
        offset += 32;

        // Get mode for originOps field
        uint8 mode = config.getFieldMode(FIELD_ORIGIN_OPS);

        // If mode is skip, always valid
        if (mode == MODE_SKIP) {
            return (true, opsHash, offset);
        }

        // Check if ops are present
        bool hasOps = opsHash != Constants.NO_OPS;

        // If mode is storage or catch-all, validate from storage
        if (mode.isStorageMode()) {
            bool required = _getOriginOpsRequirement(chainId, mode, configId, account);
            return (hasOps == required, opsHash, offset);
        }

        // If mode is sub-policy, validate from sub-policy
        if (mode.isSubPolicyMode()) {
            bool result = _validateOriginOpsSubPolicy(opsHash, chainId, configId, account, hash);
            return (result, opsHash, offset);
        }

        // Return false if no mode matched
        return (false, opsHash, offset);
    }

    /// @notice Gets originOps requirement from storage (with optional catch-all)
    function _getOriginOpsRequirement(
        uint256 chainId,
        uint8 mode,
        ConfigId configId,
        address account
    )
        private
        view
        returns (bool)
    {
        PolicyStorage storage $ = StorageLib.getPolicyStorage();

        // Get required flag from storage (with catch-all if mode == MODE_CHECK_CATCHALL)
        bool required =
            $.originOpsConfig[configId][msg.sender][account][mode.getEffectiveChainId(chainId)];

        return required;
    }

    /// @notice Validates originOps using sub-policy
    function _validateOriginOpsSubPolicy(
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
        PolicyStorage storage $ = StorageLib.getPolicyStorage();
        address policy = $.subPolicies[configId][msg.sender][account][FIELD_ORIGIN_OPS];

        // Encode the opsHash as the signature data
        bytes memory opsData = abi.encode(chainId, opsHash);

        // Call the sub-policy with the full hash and opsData
        return
            I1271Policy(policy).check1271SignedAction(configId, msg.sender, account, hash, opsData);
    }

    /*//////////////////////////////////////////////////////////////
                                DEST OPS
    //////////////////////////////////////////////////////////////*/

    /// @notice Validates destOps with mode-based routing
    function _validateDestOps(
        bytes calldata data,
        uint256 offset,
        uint256 targetChainId,
        PolicyConfig config,
        ConfigId configId,
        address account,
        bytes32 hash
    )
        private
        view
        returns (bool valid, bytes32 opsHash, uint256 newOffset)
    {
        // Read the ops hash
        opsHash = bytes32(data[offset:offset + 32]);
        offset += 32;

        // Get mode for destOps field
        uint8 mode = config.getFieldMode(FIELD_DEST_OPS);

        // If mode is skip, always valid
        if (mode == MODE_SKIP) {
            return (true, opsHash, offset);
        }

        // Check if ops are present
        bool hasOps = opsHash != Constants.NO_OPS;

        // If mode is storage or catch-all, validate from storage
        if (mode.isStorageMode()) {
            bool required = _getDestOpsRequirement(targetChainId, mode, configId, account);
            return (hasOps == required, opsHash, offset);
        }

        // If mode is sub-policy, validate from sub-policy
        if (mode.isSubPolicyMode()) {
            bool result = _validateDestOpsSubPolicy(opsHash, targetChainId, configId, account, hash);
            return (result, opsHash, offset);
        }

        // Return false if no mode matched
        return (false, opsHash, offset);
    }

    /// @notice Gets destOps requirement from storage (with optional catch-all)
    function _getDestOpsRequirement(
        uint256 targetChainId,
        uint8 mode,
        ConfigId configId,
        address account
    )
        private
        view
        returns (bool)
    {
        PolicyStorage storage $ = StorageLib.getPolicyStorage();

        // Get required flag from storage (with catch-all if mode == MODE_CHECK_CATCHALL)
        bool required = $.destOpsConfig[
            configId
        ][msg.sender][account][mode.getEffectiveChainId(targetChainId)];

        return required;
    }

    /// @notice Validates destOps using sub-policy
    function _validateDestOpsSubPolicy(
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
        PolicyStorage storage $ = StorageLib.getPolicyStorage();
        address policy = $.subPolicies[configId][msg.sender][account][FIELD_DEST_OPS];

        // Encode the opsHash as the signature data
        bytes memory opsData = abi.encode(targetChainId, opsHash);

        // Call the sub-policy with the full hash and opsData
        return
            I1271Policy(policy).check1271SignedAction(configId, msg.sender, account, hash, opsData);
    }

    /*//////////////////////////////////////////////////////////////
                             QUALIFICATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Validates qualification with mode-based routing
    function _validateQualification(
        bytes calldata data,
        uint256 offset,
        uint256 chainId,
        address arbiter,
        PolicyConfig config,
        ConfigId configId,
        address account,
        bytes32 hash
    )
        private
        view
        returns (bool valid, bytes32 qualificationHash, uint256 newOffset)
    {
        // Get mode for qualification field
        uint8 mode = config.getFieldMode(FIELD_QUALIFICATION);

        // If mode is storage or catch-all, validate from storage
        if (mode.isStorageMode()) {
            return _validateQualificationStorage(
                data, offset, chainId, mode, configId, account, arbiter
            );
        }

        // If mode is sub-policy, validate from sub-policy
        if (mode.isSubPolicyMode()) {
            return _validateQualificationSubPolicy(
                data, offset, chainId, configId, account, hash, arbiter
            );
        }

        // Return false if no mode matched
        return (false, bytes32(0), 0);
    }

    /// @notice Validates qualification using storage (with optional catch-all)
    /// @notice Validates qualification using storage (with optional catch-all)
    function _validateQualificationStorage(
        bytes calldata data,
        uint256 offset,
        uint256 chainId,
        uint8 mode,
        ConfigId configId,
        address account,
        address arbiter
    )
        private
        view
        returns (bool valid, bytes32 qualificationHash, uint256 newOffset)
    {
        // Decode qualification header
        uint256 dataLength = uint256(bytes32(data[offset:offset + 32]));
        offset += 32;

        // Decode flags
        // Two possible flags:
        // - 0x00: Use keccak256
        // - 0x01: Use arbiter hash
        uint8 flags = uint8(data[offset]);
        offset += 1;

        bytes32 qualificationTypehash = bytes32(data[offset:offset + 32]);
        offset += 32;

        // Get storage pointer
        PolicyStorage storage $ = StorageLib.getPolicyStorage();

        // Load the qualification configuration (with catch-all)
        ParamRules storage qualificationConfig = $.qualificationConfig[
            configId
        ][msg.sender][account][mode.getEffectiveChainId(chainId)][qualificationTypehash];

        // Extract qualification data
        bytes calldata qualificationData = data[offset:offset + dataLength];

        // Validate qualification data against the qualificationConfig
        if (!qualificationConfig.evaluateExpressionTree(qualificationData)) {
            return (false, bytes32(0), 0);
        }

        // Calculate qualification hash based on flags
        bool useArbiterHash = (flags & 0x01) != 0;

        // If the useArbiterHash flag is set, call the arbiter to compute the hash
        if (useArbiterHash) {
            // Call arbiter to compute hash
            qualificationHash = IArbiter(arbiter).qualificationHash(qualificationData);
        } else {
            // Use default keccak256
            qualificationHash = keccak256(qualificationData);
        }

        return (true, qualificationHash, offset + dataLength);
    }

    /// @notice Validates qualification using sub-policy
    function _validateQualificationSubPolicy(
        bytes calldata data,
        uint256 offset,
        uint256 chainId,
        ConfigId configId,
        address account,
        bytes32 hash,
        address arbiter
    )
        private
        view
        returns (bool valid, bytes32 qualificationHash, uint256 newOffset)
    {
        // Decode qualification header
        uint256 dataLength = uint256(bytes32(data[offset:offset + 32]));
        offset += 32;

        // Decode flags
        // Two possible flags:
        // - 0x00: Use keccak256
        // - 0x01: Use arbiter hash
        uint8 flags = uint8(data[offset]);
        offset += 1;

        bytes32 qualificationTypehash = bytes32(data[offset:offset + 32]);
        offset += 32;

        // Create calldata pointer to the qualification data
        bytes calldata qualificationData = data[offset:offset + dataLength];

        PolicyStorage storage $ = StorageLib.getPolicyStorage();
        address policy = $.subPolicies[configId][msg.sender][account][FIELD_QUALIFICATION];

        // Encode qualification data, chainId, and typehash as the signature data
        bytes memory qualData = abi.encode(chainId, qualificationTypehash, qualificationData);

        // Call the sub-policy
        valid = I1271Policy(policy)
            .check1271SignedAction(configId, msg.sender, account, hash, qualData);

        if (!valid) return (false, bytes32(0), 0);

        // Calculate hash for return based on flags
        bool useArbiterHash = (flags & 0x01) != 0;

        // If the useArbiterHash flag is set, call the arbiter to compute the hash
        if (useArbiterHash) {
            // Call arbiter to compute hash
            qualificationHash = IArbiter(arbiter).qualificationHash(qualificationData);
        } else {
            // Use default keccak256
            qualificationHash = keccak256(qualificationData);
        }

        return (true, qualificationHash, offset + dataLength);
    }
}
