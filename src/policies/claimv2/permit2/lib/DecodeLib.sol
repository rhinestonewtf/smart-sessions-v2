// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Contracts
import { EIP712TypeHashLib } from "@compact-utils/types/EIP712TypeHashLib.sol";

// Interfaces
import { I1271Policy } from "@smartsessions/interfaces/IPolicy.sol";

// Libraries
import { Permit2ConfigLib, PolicyConfig } from "@policies/claimv2/permit2/lib/ConfigLib.sol";
import { Permit2StorageLib, PolicyStorage } from "@policies/claimv2/permit2/lib/StorageLib.sol";
import { ArgPolicyTreeLibV2 } from "@policies/claimv2/compact/lib/ArgPolicyTreeLibV2.sol";
import { EfficientHashLib } from "@solady/utils/EfficientHashLib.sol";
import { EnumerableSetLib } from "solady/utils/EnumerableSetLib.sol";
import {
    Permit2ConfigLib as Permit2PolicyConfigLib
} from "@policies/claimv2/permit2/lib/ConfigLib.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import { ParamRules } from "@policies/claimv2/compact/types/DataTypes.sol";
import {
    MODE_SKIP,
    MODE_CHECK_STORAGE,
    MODE_CHECK_CATCHALL,
    MODE_CHECK_SUBPOLICY,
    FIELD_ARBITER,
    FIELD_DEADLINE,
    FIELD_TOKEN_IN,
    FIELD_RECIPIENT,
    FIELD_FILL_EXPIRY,
    FIELD_TOKEN_OUT,
    FIELD_ORIGIN_OPS,
    FIELD_DEST_OPS,
    FIELD_QUALIFICATION
} from "@policies/claimv2/permit2/types/DataTypes.sol";
import { Constants } from "@compact-utils/types/Constants.sol";

/// @title Decode Library
/// @notice Library for extracting and validating Permit2 + Mandate witness data from signatures
library Permit2DecodeLib {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using Permit2ConfigLib for PolicyConfig;
    using Permit2ConfigLib for bytes;
    using Permit2PolicyConfigLib for uint8;
    using ArgPolicyTreeLibV2 for ParamRules;
    using EfficientHashLib for bytes32;
    using EfficientHashLib for bytes32[];
    using EnumerableSetLib for EnumerableSetLib.AddressSet;

    /*//////////////////////////////////////////////////////////////
                                EXTRACT
    //////////////////////////////////////////////////////////////*/

    /// @notice Extracts and validates the Permit2 + Mandate data from the signature
    /// @param signature The signature data containing Permit2 and Mandate information
    /// @param config The policy configuration for this check
    /// @param configId The configuration ID for the policy
    /// @param account The account for which the policy is being validated
    /// @param hash The hash of the action to check
    /// @return valid Whether the validation was successful
    /// @return permit2Hash The reconstructed Permit2 hash
    function extractAndValidate(
        bytes calldata signature,
        PolicyConfig config,
        ConfigId configId,
        address account,
        bytes32 hash
    )
        internal
        view
        returns (bool valid, bytes32 permit2Hash)
    {
        return _decodeAndValidate(signature, config, configId, account, hash);
    }

    /*//////////////////////////////////////////////////////////////
                                 DECODE
    //////////////////////////////////////////////////////////////*/

    /// @notice Main decoding function that reconstructs and validates the Permit2 + Mandate
    /// @dev This function decodes the signature data to extract all Permit2 and Mandate fields,
    ///      validates them against the policy configuration, and reconstructs the hash
    /// @param data The signature data containing Permit2 and Mandate information
    /// @param config The policy configuration for this check
    /// @param configId The configuration ID for the policy
    /// @param account The account for which the policy is being validated
    /// @param hash The hash of the action to check
    /// @return valid Whether the validation was successful
    /// @return digest The reconstructed EIP-712 digest
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
        uint256 offset = 0;

        // Validate arbiter (Permit2 spender)
        address arbiter;
        if (config.hasCheckArbiter()) {
            bool arbiterValid;
            (arbiterValid, arbiter, offset) =
                _validateArbiter(data, offset, config, configId, account, hash);
            if (!arbiterValid) {
                return (false, bytes32(0));
            }
        } else {
            arbiter = address(bytes20(data[offset:offset + 20]));
            offset += 20;
        }

        // Decode Permit2 nonce (not validated, just read for hash)
        uint256 nonce = uint256(bytes32(data[offset:offset + 32]));
        offset += 32;

        // Decode Permit2 deadline
        uint256 deadline = uint256(bytes32(data[offset:offset + 32]));
        offset += 32;

        // Validate deadline
        if (config.hasCheckDeadline()) {
            if (!_validateDeadline(deadline, config, configId, account, hash)) {
                return (false, bytes32(0));
            }
        }

        // Validate TokenPermissions if enabled
        bytes32 tokenPermissionsHash;
        if (config.hasCheckTokenIn()) {
            bool tokenInValid;
            (tokenInValid, tokenPermissionsHash, offset) =
                _validateTokenPermissions(data, offset, config, configId, account, hash);
            if (!tokenInValid) {
                return (false, bytes32(0));
            }
        } else {
            tokenPermissionsHash = bytes32(data[offset:offset + 32]);
            offset += 32;
        }

        // Validate Mandate witness
        (bool mandateValid, bytes32 mandateHash) =
            _validateMandate(data, offset, arbiter, config, configId, account, hash);
        if (!mandateValid) {
            return (false, bytes32(0));
        }

        // Compute Permit2 witness hash
        bytes32 permitHash = EIP712TypeHashLib.hashPermit2(
            tokenPermissionsHash, arbiter, nonce, deadline, mandateHash
        );

        digest = permitHash;

        return (true, digest);
    }

    /// @notice Validates the Mandate witness struct
    /// @dev The Mandate contains all the settlement parameters that must be validated
    /// @param data The calldata containing Mandate data
    /// @param offset The current offset in the calldata
    /// @param arbiter The arbiter address (used for qualification validation)
    /// @param config The policy configuration
    /// @param configId The configuration ID
    /// @param account The account being validated
    /// @param hash The hash to validate
    /// @return valid Whether validation succeeded
    /// @return mandateHash The computed Mandate hash
    function _validateMandate(
        bytes calldata data,
        uint256 offset,
        address arbiter,
        PolicyConfig config,
        ConfigId configId,
        address account,
        bytes32 hash
    )
        private
        view
        returns (bool valid, bytes32 mandateHash)
    {
        bytes32 targetHash;
        uint256 targetChainId;

        // Validate target attributes if any checks are enabled
        if (config.hasCheckRecipient() || config.hasCheckFillExpiry() || config.hasCheckTokenOut())
        {
            bool targetValid;
            (targetValid, targetHash, targetChainId, offset) =
                _validateTarget(data, offset, config, configId, account, hash);
            if (!targetValid) {
                return (false, bytes32(0));
            }
        } else {
            targetHash = bytes32(data[offset:offset + 32]);
            offset += 32;
            targetChainId = uint256(bytes32(data[offset:offset + 32]));
            offset += 32;
        }

        // Read minGas (not validated, just read for hash)
        uint128 minGas = uint128(bytes16(data[offset:offset + 16]));
        offset += 16;

        // Validate origin ops
        bytes32 originOpsHash;
        if (config.hasCheckOriginOps()) {
            bool opsValid;
            (opsValid, originOpsHash, offset) =
                _validateOriginOps(data, offset, config, configId, account, hash);
            if (!opsValid) {
                return (false, bytes32(0));
            }
        } else {
            originOpsHash = bytes32(data[offset:offset + 32]);
            offset += 32;
        }

        // Validate dest ops
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

        // Validate qualification (with arbiter)
        bytes32 qualificationHash;
        if (config.hasCheckQualification()) {
            bool qualValid;
            (qualValid, qualificationHash, offset) =
                _validateQualification(data, offset, arbiter, config, configId, account, hash);
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

    /// @notice Validates the Target attributes struct
    /// @param data The calldata containing Target data
    /// @param offset The current offset in the calldata
    /// @param config The policy configuration
    /// @param configId The configuration ID
    /// @param account The account being validated
    /// @param hash The hash to validate
    /// @return valid Whether validation succeeded
    /// @return targetHash The computed Target hash
    /// @return targetChainId The target chain ID (needed for downstream validation)
    /// @return newOffset The updated offset after reading
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
        // Decode target attributes
        address recipient = address(bytes20(data[offset:offset + 20]));
        targetChainId = uint256(bytes32(data[offset + 32:offset + 64]));
        uint256 fillExpiry = uint256(bytes32(data[offset + 64:offset + 96]));
        offset += 96;

        // Validate recipient
        if (config.hasCheckRecipient()) {
            if (!_validateRecipient(recipient, targetChainId, config, configId, account, hash)) {
                return (false, bytes32(0), 0, 0);
            }
        }

        // Validate fill expiry
        if (config.hasCheckFillExpiry()) {
            if (!_validateFillExpiry(fillExpiry, targetChainId, config, configId, account, hash)) {
                return (false, bytes32(0), 0, 0);
            }
        }

        // Validate token out
        bytes32 tokenOutHash;
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

        // Compute Target struct hash
        targetHash = EIP712TypeHashLib.hashTargetAttributesRaw(
            recipient, tokenOutHash, targetChainId, fillExpiry
        );
        return (true, targetHash, targetChainId, offset);
    }

    /*//////////////////////////////////////////////////////////////
                               ARBITER
    //////////////////////////////////////////////////////////////*/

    /// @notice Validates the arbiter (Permit2 spender) with mode-based routing
    function _validateArbiter(
        bytes calldata data,
        uint256 offset,
        PolicyConfig config,
        ConfigId configId,
        address account,
        bytes32 hash
    )
        private
        view
        returns (bool valid, address arbiter, uint256 newOffset)
    {
        arbiter = address(bytes20(data[offset:offset + 20]));
        offset += 20;

        uint8 mode = config.getFieldMode(FIELD_ARBITER);

        if (mode == MODE_SKIP) {
            return (true, arbiter, offset);
        }

        if (mode.isStorageMode()) {
            bool isValid = _validateArbiterStorage(arbiter, configId, account);
            return (isValid, arbiter, offset);
        }

        if (mode.isSubPolicyMode()) {
            bool isValid = _validateArbiterSubPolicy(arbiter, configId, account, hash);
            return (isValid, arbiter, offset);
        }

        return (false, arbiter, offset);
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
        PolicyStorage storage $ = Permit2StorageLib.getPolicyStorage();
        address expected = $.arbiterConfig[configId][msg.sender][account];
        return arbiter == expected;
    }

    /// @notice Validates arbiter using sub-policy delegation
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
        PolicyStorage storage $ = Permit2StorageLib.getPolicyStorage();
        address policy = $.subPolicies[configId][msg.sender][account][FIELD_ARBITER];

        bytes memory arbiterData = abi.encode(arbiter);

        return
            I1271Policy(policy)
                .check1271SignedAction(configId, msg.sender, account, hash, arbiterData);
    }

    /*//////////////////////////////////////////////////////////////
                              DEADLINE
    //////////////////////////////////////////////////////////////*/

    /// @notice Validates deadline with mode-based routing
    function _validateDeadline(
        uint256 deadline,
        PolicyConfig config,
        ConfigId configId,
        address account,
        bytes32 hash
    )
        private
        view
        returns (bool)
    {
        uint8 mode = config.getFieldMode(FIELD_DEADLINE);

        if (mode == MODE_SKIP) return true;

        if (mode.isStorageMode()) {
            return _validateDeadlineStorage(deadline, configId, account);
        }

        if (mode.isSubPolicyMode()) {
            return _validateDeadlineSubPolicy(deadline, configId, account, hash);
        }

        return false;
    }

    /// @notice Validates deadline using storage bounds
    function _validateDeadlineStorage(
        uint256 deadline,
        ConfigId configId,
        address account
    )
        private
        view
        returns (bool)
    {
        PolicyStorage storage $ = Permit2StorageLib.getPolicyStorage();
        uint256 packed = $.deadlineConfig[configId][msg.sender][account];
        (uint128 min, uint128 max) = Permit2ConfigLib.unpackUint128(packed);
        return deadline >= min && deadline <= max;
    }

    /// @notice Validates deadline using sub-policy delegation
    function _validateDeadlineSubPolicy(
        uint256 deadline,
        ConfigId configId,
        address account,
        bytes32 hash
    )
        private
        view
        returns (bool)
    {
        PolicyStorage storage $ = Permit2StorageLib.getPolicyStorage();
        address policy = $.subPolicies[configId][msg.sender][account][FIELD_DEADLINE];

        bytes memory deadlineData = abi.encode(deadline);

        return I1271Policy(policy)
            .check1271SignedAction(configId, msg.sender, account, hash, deadlineData);
    }

    /*//////////////////////////////////////////////////////////////
                          TOKEN PERMISSIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Validates TokenPermissions array with mode-based routing
    function _validateTokenPermissions(
        bytes calldata data,
        uint256 offset,
        PolicyConfig config,
        ConfigId configId,
        address account,
        bytes32 hash
    )
        private
        view
        returns (bool valid, bytes32 tokenPermissionsHash, uint256 newOffset)
    {
        uint8 mode = config.getFieldMode(FIELD_TOKEN_IN);

        if (mode.isStorageMode()) {
            return _validateTokenPermissionsStorage(data, offset, mode, configId, account);
        }

        if (mode.isSubPolicyMode()) {
            return _validateTokenPermissionsSubPolicy(data, offset, configId, account, hash);
        }

        return (false, bytes32(0), 0);
    }

    /// @notice Validates TokenPermissions using storage whitelist
    function _validateTokenPermissionsStorage(
        bytes calldata data,
        uint256 offset,
        uint8 mode,
        ConfigId configId,
        address account
    )
        private
        view
        returns (bool valid, bytes32 tokenPermissionsHash, uint256 newOffset)
    {
        // Decode array length
        uint256 length = uint256(bytes32(data[offset:offset + 32]));
        offset += 32;

        // Get configured token whitelist
        PolicyStorage storage $ = Permit2StorageLib.getPolicyStorage();
        EnumerableSetLib.AddressSet storage tokenSet =
            $.tokenInSet[configId][msg.sender][account][mode.getEffectiveChainId(0)];

        if (tokenSet.length() == 0) {
            return (false, bytes32(0), 0);
        }

        // Create calldata pointer to TokenPermissions array
        uint256[2][] calldata tokenPermissions;
        assembly {
            tokenPermissions.offset := add(data.offset, offset)
            tokenPermissions.length := length
        }

        // Validate each token against whitelist
        for (uint256 i = 0; i < length; i++) {
            address token = address(uint160(tokenPermissions[i][0]));

            if (!tokenSet.contains(token)) {
                return (false, bytes32(0), 0);
            }
        }

        // Compute TokenPermissions hash
        tokenPermissionsHash = EIP712TypeHashLib.hashTokenPermissions(tokenPermissions);

        return (true, tokenPermissionsHash, offset + (length * 64));
    }

    /// @notice Validates TokenPermissions using sub-policy delegation
    function _validateTokenPermissionsSubPolicy(
        bytes calldata data,
        uint256 offset,
        ConfigId configId,
        address account,
        bytes32 hash
    )
        private
        view
        returns (bool, bytes32, uint256)
    {
        uint256 length = uint256(bytes32(data[offset:offset + 32]));
        offset += 32;

        uint256[2][] calldata tokenPermissions;
        assembly {
            tokenPermissions.offset := add(data.offset, offset)
            tokenPermissions.length := length
        }

        PolicyStorage storage $ = Permit2StorageLib.getPolicyStorage();
        address policy = $.subPolicies[configId][msg.sender][account][FIELD_TOKEN_IN];

        bytes memory tokenInData = abi.encode(tokenPermissions);

        bool valid = I1271Policy(policy)
            .check1271SignedAction(configId, msg.sender, account, hash, tokenInData);

        if (!valid) return (false, bytes32(0), 0);

        bytes32 tokenPermissionsHash = EIP712TypeHashLib.hashTokenPermissions(tokenPermissions);
        return (true, tokenPermissionsHash, offset + (length * 64));
    }

    /*//////////////////////////////////////////////////////////////
                               RECIPIENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Validates recipient address with mode-based routing
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
        uint8 mode = config.getFieldMode(FIELD_RECIPIENT);
        if (mode == MODE_SKIP) return true;

        if (mode.isStorageMode()) {
            return _validateRecipientStorage(recipient, targetChainId, mode, configId, account);
        }

        if (mode.isSubPolicyMode()) {
            return _validateRecipientSubPolicy(recipient, targetChainId, configId, account, hash);
        }

        return false;
    }

    /// @notice Validates recipient using configured address
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
        PolicyStorage storage $ = Permit2StorageLib.getPolicyStorage();
        address expected = $.recipientConfig[
            configId
        ][msg.sender][account][mode.getEffectiveChainId(targetChainId)];
        return recipient == expected;
    }

    /// @notice Validates recipient using sub-policy delegation
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
        PolicyStorage storage $ = Permit2StorageLib.getPolicyStorage();
        address policy = $.subPolicies[configId][msg.sender][account][FIELD_RECIPIENT];

        bytes memory recipientData = abi.encode(targetChainId, recipient);

        return I1271Policy(policy)
            .check1271SignedAction(configId, msg.sender, account, hash, recipientData);
    }

    /*//////////////////////////////////////////////////////////////
                              FILL EXPIRY
    //////////////////////////////////////////////////////////////*/

    /// @notice Validates fill expiry timestamp with mode-based routing
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
        uint8 mode = config.getFieldMode(FIELD_FILL_EXPIRY);
        if (mode == MODE_SKIP) return true;

        if (mode.isStorageMode()) {
            return _validateFillExpiryStorage(fillExpiry, targetChainId, mode, configId, account);
        }

        if (mode.isSubPolicyMode()) {
            return _validateFillExpirySubPolicy(fillExpiry, targetChainId, configId, account, hash);
        }

        return false;
    }

    /// @notice Validates fill expiry using configured bounds
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
        PolicyStorage storage $ = Permit2StorageLib.getPolicyStorage();
        uint256 packed = $.fillExpiryConfig[
            configId
        ][msg.sender][account][mode.getEffectiveChainId(targetChainId)];

        (uint128 min, uint128 max) = Permit2ConfigLib.unpackUint128(packed);
        return fillExpiry >= min && fillExpiry <= max;
    }

    /// @notice Validates fill expiry using sub-policy delegation
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
        PolicyStorage storage $ = Permit2StorageLib.getPolicyStorage();
        address policy = $.subPolicies[configId][msg.sender][account][FIELD_FILL_EXPIRY];

        bytes memory fillExpiryData = abi.encode(targetChainId, fillExpiry);

        return I1271Policy(policy)
            .check1271SignedAction(configId, msg.sender, account, hash, fillExpiryData);
    }

    /*//////////////////////////////////////////////////////////////
                               TOKEN OUT
    //////////////////////////////////////////////////////////////*/

    /// @notice Validates output tokens with mode-based routing
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
        uint8 mode = config.getFieldMode(FIELD_TOKEN_OUT);

        if (mode.isStorageMode()) {
            return _validateTokenOutStorage(data, offset, targetChainId, mode, configId, account);
        }

        if (mode.isSubPolicyMode()) {
            return _validateTokenOutSubPolicy(data, offset, targetChainId, configId, account, hash);
        }

        return (false, bytes32(0), 0);
    }

    /// @notice Validates token output using whitelist
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
        uint256 length = uint256(bytes32(data[offset:offset + 32]));
        offset += 32;

        PolicyStorage storage $ = Permit2StorageLib.getPolicyStorage();

        EnumerableSetLib.AddressSet storage tokenSet =
            $.tokenOutSet[configId][msg.sender][account][mode.getEffectiveChainId(targetChainId)];

        if (tokenSet.length() == 0) {
            return (false, bytes32(0), 0);
        }

        uint256[2][] calldata tokenOut;
        assembly {
            tokenOut.offset := add(data.offset, offset)
            tokenOut.length := length
        }

        for (uint256 i = 0; i < length; i++) {
            address token = address(uint160(tokenOut[i][0]));

            if (!tokenSet.contains(token)) {
                return (false, bytes32(0), 0);
            }
        }

        tokenOutHash = EIP712TypeHashLib.hashTokenOut(tokenOut);

        return (true, tokenOutHash, offset + (length * 64));
    }

    /// @notice Validates token output using sub-policy delegation
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
        uint256 length = uint256(bytes32(data[offset:offset + 32]));
        offset += 32;

        uint256[2][] calldata tokenOut;
        assembly {
            tokenOut.offset := add(data.offset, offset)
            tokenOut.length := length
        }

        PolicyStorage storage $ = Permit2StorageLib.getPolicyStorage();
        address policy = $.subPolicies[configId][msg.sender][account][FIELD_TOKEN_OUT];

        bytes memory tokenOutData = abi.encode(targetChainId, tokenOut);

        bool valid = I1271Policy(policy)
            .check1271SignedAction(configId, msg.sender, account, hash, tokenOutData);

        if (!valid) return (false, bytes32(0), 0);

        bytes32 tokenOutHash = EIP712TypeHashLib.hashTokenOut(tokenOut);
        return (true, tokenOutHash, offset + (length * 64));
    }

    /*//////////////////////////////////////////////////////////////
                               ORIGIN OPS
    //////////////////////////////////////////////////////////////*/

    /// @notice Validates origin operations requirement with mode-based routing
    function _validateOriginOps(
        bytes calldata data,
        uint256 offset,
        PolicyConfig config,
        ConfigId configId,
        address account,
        bytes32 hash
    )
        private
        view
        returns (bool valid, bytes32 opsHash, uint256 newOffset)
    {
        opsHash = bytes32(data[offset:offset + 32]);
        offset += 32;

        uint8 mode = config.getFieldMode(FIELD_ORIGIN_OPS);

        if (mode == MODE_SKIP) {
            return (true, opsHash, offset);
        }

        bool hasOps = opsHash != Constants.NO_OPS;

        if (mode.isStorageMode()) {
            bool required = _getOriginOpsRequirement(mode, configId, account);
            return (hasOps == required, opsHash, offset);
        }

        if (mode.isSubPolicyMode()) {
            bool result = _validateOriginOpsSubPolicy(opsHash, configId, account, hash);
            return (result, opsHash, offset);
        }

        return (false, opsHash, offset);
    }

    /// @notice Gets origin ops requirement from storage
    function _getOriginOpsRequirement(
        uint8 mode,
        ConfigId configId,
        address account
    )
        private
        view
        returns (bool)
    {
        PolicyStorage storage $ = Permit2StorageLib.getPolicyStorage();
        bool required =
            $.originOpsConfig[configId][msg.sender][account][mode.getEffectiveChainId(0)];
        return required;
    }

    /// @notice Validates origin ops using sub-policy delegation
    function _validateOriginOpsSubPolicy(
        bytes32 opsHash,
        ConfigId configId,
        address account,
        bytes32 hash
    )
        private
        view
        returns (bool)
    {
        PolicyStorage storage $ = Permit2StorageLib.getPolicyStorage();
        address policy = $.subPolicies[configId][msg.sender][account][FIELD_ORIGIN_OPS];

        bytes memory opsData = abi.encode(opsHash);

        return
            I1271Policy(policy).check1271SignedAction(configId, msg.sender, account, hash, opsData);
    }

    /*//////////////////////////////////////////////////////////////
                                DEST OPS
    //////////////////////////////////////////////////////////////*/

    /// @notice Validates destination operations requirement with mode-based routing
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
        opsHash = bytes32(data[offset:offset + 32]);
        offset += 32;

        uint8 mode = config.getFieldMode(FIELD_DEST_OPS);

        if (mode == MODE_SKIP) {
            return (true, opsHash, offset);
        }

        bool hasOps = opsHash != Constants.NO_OPS;

        if (mode.isStorageMode()) {
            bool required = _getDestOpsRequirement(targetChainId, mode, configId, account);
            return (hasOps == required, opsHash, offset);
        }

        if (mode.isSubPolicyMode()) {
            bool result = _validateDestOpsSubPolicy(opsHash, targetChainId, configId, account, hash);
            return (result, opsHash, offset);
        }

        return (false, opsHash, offset);
    }

    /// @notice Gets destination ops requirement from storage
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
        PolicyStorage storage $ = Permit2StorageLib.getPolicyStorage();
        bool required = $.destOpsConfig[
            configId
        ][msg.sender][account][mode.getEffectiveChainId(targetChainId)];
        return required;
    }

    /// @notice Validates destination ops using sub-policy delegation
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
        PolicyStorage storage $ = Permit2StorageLib.getPolicyStorage();
        address policy = $.subPolicies[configId][msg.sender][account][FIELD_DEST_OPS];

        bytes memory opsData = abi.encode(targetChainId, opsHash);

        return
            I1271Policy(policy).check1271SignedAction(configId, msg.sender, account, hash, opsData);
    }

    /*//////////////////////////////////////////////////////////////
                             QUALIFICATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Validates qualification data with mode-based routing (per arbiter)
    function _validateQualification(
        bytes calldata data,
        uint256 offset,
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
        uint8 mode = config.getFieldMode(FIELD_QUALIFICATION);

        if (mode.isStorageMode()) {
            return _validateQualificationStorage(data, offset, arbiter, mode, configId, account);
        }

        if (mode.isSubPolicyMode()) {
            return _validateQualificationSubPolicy(data, offset, arbiter, configId, account, hash);
        }

        return (false, bytes32(0), 0);
    }

    /// @notice Validates qualification using parameter rules (per arbiter)
    function _validateQualificationStorage(
        bytes calldata data,
        uint256 offset,
        address arbiter,
        uint8 mode,
        ConfigId configId,
        address account
    )
        private
        view
        returns (bool valid, bytes32 qualificationHash, uint256 newOffset)
    {
        uint256 dataLength = uint256(bytes32(data[offset:offset + 32]));
        offset += 32;

        PolicyStorage storage $ = Permit2StorageLib.getPolicyStorage();

        ParamRules storage qualificationConfig = $.qualificationConfig[
            configId
        ][msg.sender][account][mode.getEffectiveChainId(0)][arbiter];

        if (qualificationConfig.rules.length == 0) {
            return (false, bytes32(0), 0);
        }

        bytes calldata qualificationData = data[offset:offset + dataLength];

        if (!qualificationConfig.evaluateExpressionTree(qualificationData)) {
            return (false, bytes32(0), 0);
        }

        qualificationHash = keccak256(qualificationData);

        return (true, qualificationHash, offset + dataLength);
    }

    /// @notice Validates qualification using sub-policy delegation (per arbiter)
    function _validateQualificationSubPolicy(
        bytes calldata data,
        uint256 offset,
        address arbiter,
        ConfigId configId,
        address account,
        bytes32 hash
    )
        private
        view
        returns (bool valid, bytes32 qualificationHash, uint256 newOffset)
    {
        uint256 dataLength = uint256(bytes32(data[offset:offset + 32]));
        offset += 32;

        bytes calldata qualificationData = data[offset:offset + dataLength];

        PolicyStorage storage $ = Permit2StorageLib.getPolicyStorage();
        address policy = $.subPolicies[configId][msg.sender][account][FIELD_QUALIFICATION];

        bytes memory qualData = abi.encode(arbiter, qualificationData);

        valid = I1271Policy(policy)
            .check1271SignedAction(configId, msg.sender, account, hash, qualData);

        if (!valid) return (false, bytes32(0), 0);

        qualificationHash = keccak256(qualificationData);

        return (true, qualificationHash, offset + dataLength);
    }
}
