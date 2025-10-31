// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Contracts
import { SmartSessionManager } from "@core/SmartSessionManager.sol";
import { SmartSessionERC7739 } from "@core/SmartSessionERC7739.sol";

// Libraries
import { IdLib } from "@smartsessions/lib/IdLib.sol";
import { IdLibV2 } from "@lib/IdLibV2.sol";
import { EnumerableSet } from "@smartsessions/utils/EnumerableSet4337.sol";
import { ExecutionLib } from "@smartsessions/lib/ExecutionLib.sol";
import { PolicyLibV2 } from "@lib/PolicyLibV2.sol";
import { PolicyLib } from "@smartsessions/lib/PolicyLib.sol";
import { SignerLib } from "@smartsessions/lib/SignerLib.sol";
import { HashLib } from "@smartsessions/lib/HashLib.sol";
import { HashLibV2 } from "@lib/HashLibV2.sol";
import { SignatureCheckerLib } from "@solady/utils/SignatureCheckerLib.sol";
import { EncodeLibV2 } from "@lib/EncodeLibV2.sol";
import { DigestCacheLib } from "@lib/DigestCacheLib.sol";

// Types
import { PermissionId, PolicyType } from "@smartsessions/DataTypes.sol";
import {
    DisableSession,
    INVALID_SIGNATURE,
    NO_LOCKTAG,
    SmartSessionEmissaryConfig,
    SmartSessionEmissaryEnable,
    SmartSessionEmissaryDisable
} from "@types/DataTypes.sol";
import { Execution } from "@smartsessions/lib/ExecutionLib.sol";

/// @title SmartSessionMixin
/// @notice Mixin providing SmartSession functionality for emissaries
/// @dev Bridges lockTag-based emissary system with permissionId-based SmartSession system
abstract contract SmartSessionMixin is SmartSessionManager, SmartSessionERC7739 {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using EncodeLibV2 for *;
    using IdLib for *;
    using IdLibV2 for *;
    using EnumerableSet for *;
    using ExecutionLib for *;
    using PolicyLib for *;
    using PolicyLibV2 for *;
    using SignerLib for *;
    using HashLib for *;
    using HashLibV2 for *;
    using SignatureCheckerLib for *;
    using DigestCacheLib for *;

    /*//////////////////////////////////////////////////////////////
                                CONFIG
    //////////////////////////////////////////////////////////////*/

    /// @notice Sets the Smart Session Emissary configuration for a specific account
    /// @param account The address of the account for which the configuration is being set
    /// @param config The Smart Session Emissary configuration
    /// @param enableData The Emissary enable data
    function setConfig(
        address account,
        SmartSessionEmissaryConfig calldata config,
        SmartSessionEmissaryEnable calldata enableData
    )
        public
    {
        // Derive lockTag from allocator, scope, resetPeriod
        bytes12 lockTag = config.allocator.deriveLockTag(config.scope, config.resetPeriod);

        // Verify data expires after current block timestamp
        require(enableData.expires > block.timestamp, InvalidEmissaryEnableData());

        // Enable policies
        _enableSession(account, enableData, config, lockTag);

        // Emit event if the session is enabled
        emit SmartSessionEmissaryConfigUpdated(account, config.permissionId, lockTag);
    }

    /// @notice Removes a Smart Session Emissary configuration for a specific account
    /// @param account The address of the account for which the configuration is being removed
    /// @param config The Smart Session Emissary configuration to be removed
    /// @param disableData The disable data containing the allocatorSignature, user signature,
    ///                    disable session data, and expiration time
    function removeConfig(
        address account,
        SmartSessionEmissaryConfig calldata config,
        SmartSessionEmissaryDisable calldata disableData
    )
        external
    {
        // Derive lockTag from allocator, scope, resetPeriod
        bytes12 lockTag = config.allocator.deriveLockTag(config.scope, config.resetPeriod);

        // Verify data expires after current block timestamp
        require(disableData.expires > block.timestamp, InvalidEmissaryDisableData());

        // Disable sessions
        _disableSessions(
            account,
            disableData.session,
            config.permissionId,
            config.sender,
            lockTag,
            disableData.expires,
            config.allocator,
            disableData.allocatorSig,
            disableData.userSig
        );

        // Emit event if the session is removed
        emit SmartSessionEmissaryConfigUpdated(account, config.permissionId, lockTag);
    }

    /*//////////////////////////////////////////////////////////////
                                 CLAIM
    //////////////////////////////////////////////////////////////*/

    /// @notice Verifies digests using SmartSession (mode 2)
    /// @param sponsor The sponsor account associated with the claim
    /// @param claimHash The hash of the claim being verified
    /// @param emissaryData Data containing the permissionId and signature
    /// @param lockTag The lock tag associated with the claim
    /// @return result The verifyClaim selector if valid, otherwise 0xffffffff
    function _verifyClaimSmartSession(
        address sponsor,
        bytes32 claimHash,
        bytes calldata emissaryData,
        bytes12 lockTag
    )
        internal
        view
        virtual
        returns (bytes4 result)
    {
        bool success = _claimIsValidSignatureNowCalldata(
            msg.sender, claimHash, emissaryData, sponsor, lockTag
        );
        /// @solidity memory-safe-assembly
        // solhint-disable-next-line no-inline-assembly
        assembly {
            // `success ? bytes4(keccak256("verifyClaim(address,bytes32,bytes32,bytes,bytes12)")) :
            // 0xffffffff`.
            result := shl(224, or(0xf699ba1c, sub(0, iszero(success))))
        }
    }

    /*//////////////////////////////////////////////////////////////
                               EXECUTION
    //////////////////////////////////////////////////////////////*/

    /// @notice Validates executions using SmartSession policies
    /// @param account The account for which the policies are being enforced
    /// @param hash The hash of the user operation
    /// @param emissaryData Packed smart session data including mode, permissionId and signature
    /// @param executions The execution data for the user operation
    /// @param lockTag The lock tag associated with the execution configuration
    /// @return bytes4 The function selector on success, or a specific failure code otherwise
    function _verifyExecutionSmartSession(
        address account,
        bytes32 hash,
        bytes calldata emissaryData,
        Execution[] calldata executions,
        bytes12 lockTag
    )
        internal
        virtual
        returns (bytes4)
    {
        // Init validSig
        bool validSig;

        // unpacking data packed in data
        (PermissionId permissionId, bytes calldata packedSig) = emissaryData.unpack();

        // Enforce action policies
        validSig = _enforceActionPolicies({
            permissionId: permissionId,
            hash: hash,
            executions: executions,
            decompressedSignature: packedSig,
            account: account,
            lockTag: lockTag
        });

        // Return the function selector on success, or a specific failure code otherwise.
        return validSig ? this.verifyExecution.selector : INVALID_SIGNATURE;
    }

    /*//////////////////////////////////////////////////////////////
                                INTERNAL
    //////////////////////////////////////////////////////////////*/

    /// @notice Enforces action policies and checks ISessionValidator signature for a session
    /// @dev This function is the core of policy enforcement in SmartSession
    /// @param permissionId The unique identifier for the permission set
    /// @param hash Message hash to be validated
    /// @param executions The execution data for the user operation
    /// @param decompressedSignature The decompressed signature for validation
    /// @param account The account for which policies are being enforced
    /// @param lockTag The lock tag associated with the session
    /// @return validSig True if the signature is valid, false otherwise
    function _enforceActionPolicies(
        PermissionId permissionId,
        bytes32 hash,
        Execution[] calldata executions,
        bytes memory decompressedSignature,
        address account,
        bytes12 lockTag
    )
        internal
        returns (bool validSig)
    {
        // ensure that the permissionId is enabled for the sender, account, and lockTag
        if (!$lockTagPermissions[lockTag].contains(account, PermissionId.unwrap(permissionId))) {
            revert InvalidPermissionId(permissionId);
        }

        /*//////////////////////////////////////////////////////////////
                                HANDLE EXECUTIONS
        //////////////////////////////////////////////////////////////*/

        // Check action policies for the given permissionId and batch execution
        $actionPolicies.actionPolicies
            .checkBatch7579Exec({
                executions: executions,
                permissionId: permissionId,
                minPolicies: 1, // minimum of one actionPolicy must be set.
                account: account
            });

        /*//////////////////////////////////////////////////////////////
                                CHECK SESSION KEY
        //////////////////////////////////////////////////////////////*/

        // Calculate digest using 712
        bytes32 digest = _hashTypedDataV4(hash);

        // Check if this digest was already validated
        if (digest.isAlreadyVerified(account, permissionId, lockTag)) {
            return true;
        }

        // perform signature check with ISessionValidator
        // this function will revert if no ISessionValidator is set for this permissionId
        validSig = $sessionValidators.isValidISessionValidator({
            hash: digest,
            account: account,
            permissionId: permissionId,
            signature: decompressedSignature
        });

        // Cache the result if valid
        if (validSig) {
            digest.markAsVerified(account, permissionId, lockTag);
        }
    }

    /// @notice Validates an ERC-1271 signature
    /// @dev This function performs several checks to validate the signature:
    ///      1. Verifies that the permissionId is enabled for the lockTag and account
    ///      2. Extracts the session validator signature using the provided length
    ///      3. Checks the ERC-1271 policy with the remaining policy data
    ///      4. Validates the signature using ISessionValidator
    /// @dev Signature format:
    /// [permissionId(32)][sigLength(32)][validatorSig(sigLength)][policyData]
    /// @param hash The hash of the data to be signed
    /// @param signature The signature to be validated
    /// @param sponsor The address of the account for which the signature is being validated
    /// @param lockTag The lock tag associated with the session
    /// @return valid Boolean indicating whether the signature is valid
    function _claimIsValidSignatureNowCalldata(
        address sender,
        bytes32 hash,
        bytes calldata signature,
        address sponsor,
        bytes12 lockTag
    )
        internal
        view
        returns (bool)
    {
        // isolate the PermissionId and actual signature from the supplied signature param
        PermissionId permissionId = PermissionId.wrap(bytes32(signature[0:32]));

        // forgefmt: disable-next-item
        if (
            // return false if permissionId is not enabled for lockTag and sender
             !$lockTagPermissions[lockTag].contains(
                sponsor, PermissionId.unwrap(permissionId)
            )
        ) return false;

        // Extract the offset for the policy data
        uint256 policyDataOffset = uint256(bytes32(signature[32:64]));

        // check the claim policy
        bool valid = $erc1271Policies.checkERC1271({
            account: sponsor,
            requestSender: sender,
            hash: hash,
            signature: signature[policyDataOffset:], // extract the policy data after the
                // validator signature
            permissionId: permissionId,
            configId: permissionId.toErc1271PolicyId().toConfigId(sponsor),
            minPoliciesToEnforce: 1
        });

        // if the claim policy check failed, return false
        if (!valid) return valid;

        // Calculate digest using 712
        bytes32 digest = _hashTypedDataV4(hash);

        // Check if this digest was already validated
        if (digest.isAlreadyVerified(sponsor, permissionId, lockTag)) {
            return true;
        }

        // this call reverts if the ISessionValidator is not set
        return $sessionValidators.isValidISessionValidator({
            hash: digest,
            account: sponsor,
            permissionId: permissionId,
            signature: signature[64:policyDataOffset] // extract the validator signature
        });
    }

    /// @notice Validates an ERC-1271 signature with additional ERC-7739 content checks
    /// @dev This function performs several checks to validate the signature:
    ///      1. Verifies that the permissionId is enabled for the msg.sender
    ///      2. Ensures the ERC-7739 content is enabled for the given permissionId
    ///      3. Checks the ERC-1271 policy
    ///      4. Validates the signature using ISessionValidator
    /// @dev This function returns false if a permissionId supplied within the signature is not
    /// enabled @dev This function returns false if the ERC-7739 content is not enabled for the
    /// given permissionId
    /// @param sender The address initiating the signature validation
    /// @param hash The hash of the data to be signed
    /// @param signature The signature to be validated (first 32 bytes contain the permissionId)
    /// @param contents The ERC-7739 content to be validated
    /// @return valid Boolean indicating whether the signature is valid
    function _erc1271IsValidSignatureNowCalldata(
        address sender,
        bytes32 hash,
        bytes calldata signature,
        bytes32 appDomainSeparator,
        bytes calldata contents
    )
        internal
        view
        virtual
        override
        returns (bool)
    {
        bytes32 contentHash = string(contents).hashERC7739Content();
        // isolate the PermissionId and actual signature from the supplied signature param
        PermissionId permissionId = PermissionId.wrap(bytes32(signature[0:32]));
        signature = signature[32:];

        // forgefmt: disable-next-item
        if (
            // return false if permissionId is not enabled for msg.sender
            !$lockTagPermissions[NO_LOCKTAG].contains(
                msg.sender, PermissionId.unwrap(permissionId)
            ) ||
            // return false if the content is not enabled
            !$enabledERC7739.enabledContentNames[permissionId][appDomainSeparator].contains(msg.sender, contentHash)
        ) return false;

        // Extract the offset for the policy data
        uint256 policyDataOffset = uint256(bytes32(signature[32:64]));

        // check the ERC-1271 policy
        bool valid = $erc1271Policies.checkERC1271({
            account: msg.sender,
            requestSender: sender,
            hash: hash,
            signature: signature[policyDataOffset:], // extract the policy data after the
                // validator signature
            permissionId: permissionId,
            configId: permissionId.toErc1271PolicyId().toConfigId(),
            minPoliciesToEnforce: 1
        });

        // TODO: Do we want do do digest caching here as well?

        // if the erc1271 policy check failed, return false
        if (!valid) return valid;
        // this call reverts if the ISessionValidator is not set
        return $sessionValidators.isValidISessionValidator({
            hash: hash,
            account: msg.sender,
            permissionId: permissionId,
            signature: signature[64:policyDataOffset] // extract the validator signature
        });
    }

    /*//////////////////////////////////////////////////////////////
                                VIRTUAL
    //////////////////////////////////////////////////////////////*/

    /// @notice Returns the typed data hash for a given hash
    function _getTypedDataHashSansChainId(bytes32 hash) internal view virtual returns (bytes32);

    /// @notice Returns the typed data hash for a given hash
    function _hashTypedDataV4(bytes32 hash) internal view virtual returns (bytes32);
}
