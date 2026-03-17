// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

// Contracts
import { SmartSessionManager } from "@core/SmartSessionManager.sol";
import { SmartSessionERC7739 } from "@core/SmartSessionERC7739.sol";

// Interfaces
import { ISmartSessionEmissary } from "@interfaces/ISmartSessionEmissary.sol";

// Libraries
import { IdLib } from "@smartsessions/lib/IdLib.sol";
import { IdLibV2 } from "@lib/IdLibV2.sol";
import { EnumerableSet } from "@smartsessions/utils/EnumerableSet4337.sol";
import { PolicyLibV2 } from "@lib/PolicyLibV2.sol";
import { PolicyLib } from "@smartsessions/lib/PolicyLib.sol";
import { SignerLib } from "@smartsessions/lib/SignerLib.sol";
import { HashLib } from "@smartsessions/lib/HashLib.sol";
import { EncodeLibV2 } from "@lib/EncodeLibV2.sol";
import { DigestCacheLib } from "@lib/DigestCacheLib.sol";
import { SmartExecutionLib } from "@compact-utils/common/SmartExecutionLib.sol";
import { ExecutionLibV2 } from "@lib/ExecutionLibV2.sol";
import { ECDSA } from "solady/utils/ECDSA.sol";

// Types
import { PermissionId, SmartSessionMode } from "@smartsessions/DataTypes.sol";
import {
    SmartSessionEmissaryConfig,
    SmartSessionEmissaryEnable,
    SmartSessionEmissaryDisable,
    EMPTY_CONTENT_HASH
} from "@types/DataTypes.sol";
import { Execution } from "@smartsessions/lib/ExecutionLib.sol";
import { Types } from "@rhinestone/compact-utils/src/types/OrderTypes.sol";

/// @title SmartSessionMixin
/// @notice Mixin providing SmartSession functionality for emissaries
/// @dev Bridges lockTag-based emissary system with permissionId-based SmartSession system
abstract contract SmartSessionMixin is
    SmartSessionManager,
    SmartSessionERC7739,
    ISmartSessionEmissary
{
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using IdLib for *;
    using IdLibV2 for *;
    using EnumerableSet for *;
    using ExecutionLibV2 for *;
    using PolicyLib for *;
    using PolicyLibV2 for *;
    using SignerLib for *;
    using HashLib for *;
    using DigestCacheLib for *;
    using SmartExecutionLib for *;
    using EncodeLibV2 for *;

    /*//////////////////////////////////////////////////////////////
                                 CLAIM
    //////////////////////////////////////////////////////////////*/

    /// @notice Verifies digests using SmartSession (mode 2)
    /// @param sponsor The sponsor account associated with the claim
    /// @param digest The digest of the claim being verified
    /// @param emissaryData Data containing the permissionId and signature
    /// @param lockTag The lock tag associated with the claim
    /// @return result The verifyClaim selector if valid, otherwise 0xffffffff
    function _verifyClaimSmartSession(
        address sponsor,
        bytes32 digest,
        bytes calldata emissaryData,
        bytes12 lockTag
    )
        internal
        view
        virtual
        returns (bytes4 result)
    {
        bool success = _claimIsValidSignatureNowCalldata({
            sender: msg.sender,
            digest: digest,
            signature: emissaryData,
            sponsor: sponsor,
            lockTag: lockTag
        });
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
    /// @param digest The digest of claim being verified which includes executions
    /// @param emissaryData Packed smart session data including mode, permissionId and signature
    /// @param executions The execution data for the user operation
    /// @return result The function selector on success, or a specific failure code otherwise
    function _verifyExecutionSmartSession(
        address account,
        bytes32 digest,
        bytes calldata emissaryData,
        Types.Operation calldata executions
    )
        internal
        virtual
        returns (bytes4 result)
    {
        // Init validSig
        bool validSig;

        // Unpack mode, permissionId and signature from emissaryData
        (SmartSessionMode mode, PermissionId permissionId, bytes calldata packedSig) =
            emissaryData.unpackMode();

        // If the SmartSession.USE mode was selected, no further policies have to be enabled.
        // We can go straight to userOp validation
        // This condition is the average case, so should be handled as the first condition
        if (mode == SmartSessionMode.USE) {
            validSig = _enforceActionPolicies({
                permissionId: permissionId,
                digest: digest,
                executions: executions.safeToERC7579().parse(),
                decompressedSignature: packedSig,
                account: account
            });
        }
        // If the SmartSession.ENABLE mode was selected, the userOp.signature will contain the
        // EnableSession data This data will be used to enable policies and signer for the session
        // The signature of the user on the EnableSession data will be checked
        // If the signature is valid, the policies and signer will be enabled
        // after enabling the session, the policies will be enforced on the userOp similarly to the
        // SmartSession.USE
        else if (mode == SmartSessionMode.ENABLE) {
            // unpack the EnableSession data and signature
            // calculate the permissionId from the Session data
            (
                SmartSessionEmissaryEnable memory enableData,
                SmartSessionEmissaryConfig memory config,
                bytes memory usePermissionSig
            ) = packedSig.decodeEnable();
            permissionId = enableData.session.sessionToEnable.toPermissionIdMemory();

            // ENABLE mode: Enable new policies and then enforce them
            _enableSession({
                account: account, enableData: enableData, config: config, permissionId: permissionId
            });

            validSig = _enforceActionPolicies({
                permissionId: permissionId,
                digest: digest,
                executions: executions.safeToERC7579().parse(),
                decompressedSignature: usePermissionSig,
                account: account
            });
        }
        // if an Unknown mode is provided, the function will revert
        else {
            revert UnsupportedSmartSessionMode(mode);
        }

        /// @solidity memory-safe-assembly
        assembly {
            // validSig ?
            // bytes4(keccak256("verifyExecution(address,bytes32,bytes,Types.Operation,bytes12)")) :
            // 0xffffffff`. We use `0xffffffff` for invalid signatures.
            result := shl(224, or(0x043b31ea, sub(0, iszero(validSig))))
        }
    }

    /*//////////////////////////////////////////////////////////////
                                INTERNAL
    //////////////////////////////////////////////////////////////*/

    /// @notice Enforces action policies and checks ISessionValidator signature for a session
    /// @dev This function is the core of policy enforcement in SmartSession
    /// @param permissionId The unique identifier for the permission set
    /// @param digest Message digest to be validated
    /// @param executions The execution data for the user operation
    /// @param decompressedSignature The decompressed signature for validation
    /// @param account The account for which policies are being enforced
    /// @return validSig True if the signature is valid, false otherwise
    function _enforceActionPolicies(
        PermissionId permissionId,
        bytes32 digest,
        Execution[] calldata executions,
        bytes memory decompressedSignature,
        address account
    )
        internal
        virtual
        returns (bool validSig)
    {
        // ensure that the permissionId is enabled for the sender, account, and lockTag
        if (!$enabledSessions.contains({
                account: account, value: PermissionId.unwrap(permissionId)
            })) {
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

        // Check if this digest was already validated
        if (digest.isAlreadyVerified({ account: account, permissionId: permissionId })) {
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
            digest.markAsVerified({ account: account, permissionId: permissionId });
        }
    }

    /// @notice Validates an ERC-1271 signature
    /// @dev This function performs several checks to validate the signature:
    ///      1. Verifies that the permissionId is enabled for the lockTag and account
    ///      2. Extracts the session validator signature using the provided length
    ///      3. Checks the ERC-1271 policy with the remaining policy data
    ///      4. Validates the signature using ISessionValidator
    /// @dev Signature format:
    /// [permissionId(32)][policyDataOffset(32)][validatorSig(sigLength)][policyData]
    /// @param digest The digest of the data to be signed
    /// @param signature The signature to be validated
    /// @param sponsor The address of the account for which the signature is being validated
    /// @param lockTag The lock tag associated with the session
    /// @return valid Boolean indicating whether the signature is valid
    function _claimIsValidSignatureNowCalldata(
        address sender,
        bytes32 digest,
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
             !$enabledSessions.contains(
               {account: sponsor, value: PermissionId.unwrap(permissionId)}
            )
        ) return false;

        // Extract the offset for the policy data
        uint256 policyDataOffset = uint256(bytes32(signature[32:64]));

        // check the claim policy
        bool valid = $claimPolicies[lockTag].checkERC1271({
            account: sponsor,
            requestSender: sender,
            hash: digest,
            signature: signature[policyDataOffset:], // extract the policy data after the
            // validator signature
            permissionId: permissionId,
            configId: permissionId.toErc1271PolicyId().toConfigId(sponsor),
            minPoliciesToEnforce: 1
        });

        // if the claim policy check failed, return false
        if (!valid) return valid;

        // Check if this digest was already validated
        if (digest.isAlreadyVerified({ account: sponsor, permissionId: permissionId })) {
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

    /// @notice Validates an ERC-1271 signature with optional ERC-7739 content checks
    /// @dev This function supports two validation modes based on the appDomainSeparator:
    ///
    ///      **Direct Mode (appDomainSeparator = bytes32(0)):**
    ///      1. Verifies that the permissionId is enabled for msg.sender
    ///      2. Requires explicit allowlist for domain 0 (opt-in for direct mode)
    ///      3. Checks the ERC-1271 policy with the raw hash
    ///      4. Binds hash to msg.sender via simple keccak256(abi.encode(msg.sender, hash))
    ///      5. Validates signature using ISessionValidator with the account-bound digest
    ///
    ///      **ERC-7739 Mode (appDomainSeparator != bytes32(0)):**
    ///      1. Verifies that the permissionId is enabled for msg.sender
    ///      2. Ensures the ERC-7739 content hash is enabled for the given permissionId and domain
    ///      3. Checks the ERC-1271 policy with the raw hash
    ///      4. Validates signature using ISessionValidator with the ERC-7739 wrapped hash
    ///         (hash is already fully wrapped by _erc1271IsValidSignatureViaNestedEIP712)
    ///
    /// @dev Direct mode skips ERC-7739 nested wrapping for session keys signing programmatically.
    ///      Since session keys don't need human-readable signature prompts, we can use simple
    ///      and cheap account binding. This is ideal for where the signature is generated by code
    ///      rather than shown to a user.
    ///
    ///      To use direct mode, the session must explicitly enable domain 0 via
    ///      allowedERC7739Content to prevent accidental bypass of ERC-7739 restrictions.
    ///
    /// @param sender The address initiating the signature validation
    /// @param hash The hash of the data to be signed (in ERC-7739 mode, already fully wrapped)
    /// @param signature The signature to be validated
    ///        Format: [permissionId(32)][policyDataOffset(32)][validatorSig][policyData]
    /// @param appDomainSeparator The app's domain separator (bytes32(0) = direct mode)
    /// @param contents The ERC-7739 content to be validated (empty in direct mode)
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
        // Extract the PermissionId from the signature
        PermissionId permissionId = PermissionId.wrap(bytes32(signature[0:32]));

        // Check if permissionId is enabled for msg.sender
        if (!$enabledSessions.contains({
                account: msg.sender, value: PermissionId.unwrap(permissionId)
            })) {
            return false;
        }

        // Detect direct mode (skip ERC-7739 wrapping)
        bool directMode = appDomainSeparator == bytes32(0);

        // Init contentHash to EMPTY_CONTENT_HASH
        bytes32 contentHash = EMPTY_CONTENT_HASH;

        // If we're not using direct mode, calculate the contents hash
        if (!directMode) {
            contentHash = string(contents).hashERC7739Content();
        }

        // Check that the content hash is enabled for the given permissionId and appDomainSeparator
        if (!$enabledERC7739.enabledContentNames[permissionId][appDomainSeparator].contains({
                account: msg.sender, value: contentHash
            })) {
            return false;
        }

        // Extract the offset for the policy data
        uint256 policyDataOffset = uint256(bytes32(signature[32:64]));

        // Check the ERC-1271 policy
        bool valid = $erc1271Policies.checkERC1271({
            account: msg.sender,
            requestSender: sender,
            hash: hash,
            signature: signature[policyDataOffset:],
            permissionId: permissionId,
            configId: permissionId.toErc1271PolicyId().toConfigId(),
            minPoliciesToEnforce: 1
        });

        if (!valid) return false;

        // Determine the digest based on mode:
        // 1) Direct mode: Hash bound to msg.sender and wrapped via ERC191 toEthSignedMessageHash
        // 2) ERC-7739 mode: Hash wrapped via ERC7739 _erc1271IsValidSignatureViaNestedEIP712
        bytes32 digest =
            directMode ? ECDSA.toEthSignedMessageHash(abi.encode(msg.sender, hash)) : hash;

        // Validate signature using ISessionValidator
        return $sessionValidators.isValidISessionValidator({
            hash: digest,
            account: msg.sender,
            permissionId: permissionId,
            signature: signature[64:policyDataOffset]
        });
    }

    /*//////////////////////////////////////////////////////////////
                                VIRTUAL
    //////////////////////////////////////////////////////////////*/

    /// @notice Returns the typed data hash for a given hash
    function _getTypedDataHashSansChainId(bytes32 hash) internal view virtual returns (bytes32);
}
