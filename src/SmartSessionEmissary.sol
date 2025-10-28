// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Contracts
import { Emissary as VanillaEmissary } from "@compact-utils/emissary/Emissary.sol";
import { SmartSessionMixin } from "@core/SmartSessionMixin.sol";
import { EIP712 } from "@solady/utils/EIP712.sol";
import { ERC7579ValidatorBase } from "@modulekit/module-bases/ERC7579ValidatorBase.sol";

// Interfaces
import { ISmartSessionEmissary } from "@interfaces/ISmartSessionEmissary.sol";

// Libraries
import { ModeLib, EmissaryMode, EMISSARY_VANILLA, EMISSARY_SMART_SESSION } from "@lib/ModeLib.sol";

// Types
import { INVALID_SIGNATURE } from "@types/DataTypes.sol";
import { PackedUserOperation } from "@modulekit/external/ERC4337.sol";
import { Execution } from "@smartsessions/lib/ExecutionLib.sol";

/// @title Smart Session Emissary
/// @notice A 7579 1271 validator that also serves as an emissary supporting both vanilla and
///         Smart Session signature verification and execution validation.
contract SmartSessionEmissary is VanillaEmissary, SmartSessionMixin {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    /// @dev Used to decode emissary mode from emissary data
    using ModeLib for bytes;

    /*//////////////////////////////////////////////////////////////
                                  1271
    //////////////////////////////////////////////////////////////*/

    /// @notice SessionKey ERC-1271 signature validation
    ///         this function implements the ERC-1271 forwarding function defined by ERC-7579
    ///         SessionKeys can be used to sign messages and validate ERC-1271 on behalf of Accounts
    ///         In order to validate a signature, the signature must be wrapped with ERC-7739
    /// @param sender The address of ERC-1271 sender
    /// @param hash The hash of the message
    /// @param signature The signature of the message
    ///        signature is expected to be in the format:
    ///       (PermissionId (32 bytes),
    ///        ERC7739 (abi.encodePacked(signatureForSessionValidator,
    ///                                  _DOMAIN_SEP_B,
    ///                                  contents,
    ///                                  contentsType,
    ///                                  uint16(contentsType.length))
    function isValidSignatureWithSender(
        address sender,
        bytes32 hash,
        bytes calldata signature
    )
        external
        view
        returns (bytes4 result)
    {
        // ERC-7739 support detection
        if (hash == 0x7739773977397739773977397739773977397739773977397739773977397739) {
            return bytes4(0x77390001);
        }
        // disallow that session can be authorized by other sessions
        if (sender == address(this)) return INVALID_SIGNATURE;
        bool success = _erc1271IsValidSignatureViaNestedEIP712(
            sender, hash, _erc1271UnwrapSignature(signature[12:])
        );
        /// @solidity memory-safe-assembly
        assembly {
            // `success ? bytes4(keccak256("isValidSignature(bytes32,bytes)")) : 0xffffffff`.
            // We use `0xffffffff` for invalid, in convention with the reference implementation.
            result := shl(224, or(0x1626ba7e, sub(0, iszero(success))))
        }
    }

    /*//////////////////////////////////////////////////////////////
                                 CLAIM
    //////////////////////////////////////////////////////////////*/

    /// @notice Verifies claims with mode-based dispatch to appropriate verification method
    /// @param sponsor The sponsor account associated with the claim
    /// @param digest The digest of the claim hash
    /// @param emissaryData Data containing mode byte and mode-specific verification data
    /// @param lockTag The lock tag associated with the claim
    /// @return The selector if valid, otherwise 0xFFFFFFFF
    function verifyClaim(
        address sponsor,
        bytes32 digest,
        bytes32 claimHash,
        bytes calldata emissaryData,
        bytes12 lockTag
    )
        public
        view
        override(VanillaEmissary, ISmartSessionEmissary)
        returns (bytes4)
    {
        // Extract mode from first byte of emissaryData
        EmissaryMode mode = emissaryData.decodeMode();

        // Mode-based dispatch for claim verification
        if (mode == EMISSARY_VANILLA) {
            // Validate using vanilla emissary signature validation
            return _validateSignature(sponsor, digest, emissaryData, lockTag)
                ? this.verifyClaim.selector
                : INVALID_SIGNATURE;
        } else if (mode == EMISSARY_SMART_SESSION) {
            // Validate using SmartSession verification
            return _verifyClaimSmartSession(sponsor, claimHash, emissaryData[1:], lockTag);
        }

        // Default case for unsupported modes
        return INVALID_SIGNATURE;
    }

    /*//////////////////////////////////////////////////////////////
                               EXECUTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Validates executions using mode-based dispatch
    /// @param sponsor The account for which the policies are being enforced
    /// @param digest The hash of the user operation
    /// @param emissaryData Data containing mode and mode-specific execution data
    /// @param executions The execution data for the user operation
    /// @param lockTag The lock tag associated with the execution configuration
    /// @return bytes4 The function selector on success, or a specific failure code otherwise
    function verifyExecution(
        address sponsor,
        bytes32 digest,
        bytes calldata emissaryData,
        Execution[] calldata executions,
        bytes12 lockTag
    )
        public
        returns (bytes4)
    {
        // Extract mode from first byte
        EmissaryMode mode = emissaryData.decodeMode();

        // Mode-based dispatch for execution verification
        if (mode == EMISSARY_VANILLA) {
            // Validate using vanilla emissary signature validation
            return _validateSignature(sponsor, digest, emissaryData, lockTag)
                ? this.verifyExecution.selector
                : INVALID_SIGNATURE;
        } else if (mode == EMISSARY_SMART_SESSION) {
            // Validate using SmartSession verification
            return
                _verifyExecutionSmartSession(sponsor, digest, emissaryData[1:], executions, lockTag);
        }

        // Default case for unsupported modes
        return INVALID_SIGNATURE;
    }

    /*//////////////////////////////////////////////////////////////
                                  712
    //////////////////////////////////////////////////////////////*/

    /// @notice Returns the EIP-712 domain name and version
    /// @dev Used in the EIP-712 signature hashing process.
    /// @return name The EIP-712 domain name
    /// @return version The EIP-712 domain version
    function _domainNameAndVersion()
        internal
        view
        virtual
        override
        returns (string memory name, string memory version)
    {
        name = "SmartSessionEmissary";
        version = "0.0.1";
    }

    /// @notice Returns the EIP-712 typed data hash for a given hash without chain ID
    function _getTypedDataHashSansChainId(bytes32 hash)
        internal
        view
        override(SmartSessionMixin)
        returns (bytes32)
    {
        return _hashTypedDataSansChainId(hash);
    }

    /// @notice Returns the EIP-712 typed data hash for a given hash with chain ID
    function _hashTypedDataV4(bytes32 hash)
        internal
        view
        override(SmartSessionMixin)
        returns (bytes32)
    {
        return _hashTypedData(hash);
    }
}
