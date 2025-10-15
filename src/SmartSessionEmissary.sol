// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Contracts
import { EmissaryBase } from "@core/EmissaryBase.sol";
import { SmartSessionMixin } from "@core/SmartSessionMixin.sol";
import { EIP712 } from "@solady/utils/EIP712.sol";

// Libraries
import {
    ModeLib,
    EmissaryMode,
    EMISSARY_STATELESS_VALIDATOR,
    EMISSARY_ECDSA,
    EMISSARY_PASSKEY,
    EMISSARY_SMART_SESSION
} from "@lib/ModeLib.sol";

// Types
import { INVALID_RETURN } from "@types/DataTypes.sol";
import { Execution } from "@smartsessions/lib/ExecutionLib.sol";

/// @title Smart Session Emissary
/// @notice An extended emissary contract that supports multiple verification modes including
///         SmartSessions, stateless validators, and ECDSA/Passkey configurations.
contract SmartSessionEmissary is EmissaryBase, SmartSessionMixin, EIP712 {
    /* //////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using ModeLib for bytes;

    /* //////////////////////////////////////////////////////////////
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
        bytes32, /* / claimHash */
        bytes calldata emissaryData,
        bytes12 lockTag
    )
        public
        view
        returns (bytes4)
    {
        // Extract mode from first byte of emissaryData
        EmissaryMode mode = emissaryData.decodeMode();

        // Mode-based dispatch for claim verification
        if (mode == EMISSARY_STATELESS_VALIDATOR) {
            // Stateless Validator mode
            return _verifyClaimStatelessValidator(sponsor, digest, emissaryData[1:], lockTag);
        } else if (mode == EMISSARY_ECDSA) {
            // ECDSA mode
            return _verifyClaimECDSA(sponsor, digest, emissaryData[1:], lockTag);
        } else if (mode == EMISSARY_PASSKEY) {
            // Passkey mode
            return _verifyClaimPasskey(sponsor, digest, emissaryData[1:], lockTag);
        } else if (mode == EMISSARY_SMART_SESSION) {
            // SmartSession mode
            return _verifyClaimSmartSession(sponsor, digest, emissaryData[1:], lockTag);
        }

        // Default case for unsupported modes
        return INVALID_RETURN;
    }

    /* //////////////////////////////////////////////////////////////
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
        if (mode == EMISSARY_STATELESS_VALIDATOR) {
            // Stateless Validator mode
            return _verifyExecutionStatelessValidator(
                sponsor, digest, emissaryData[1:], executions, lockTag
            );
        } else if (mode == EMISSARY_ECDSA) {
            // ECDSA mode
            return _verifyExecutionECDSA(sponsor, digest, emissaryData[1:], executions, lockTag);
        } else if (mode == EMISSARY_PASSKEY) {
            // Passkey mode
            return _verifyExecutionPasskey(sponsor, digest, emissaryData[1:], executions, lockTag);
        } else if (mode == EMISSARY_SMART_SESSION) {
            // SmartSession mode
            return
                _verifyExecutionSmartSession(sponsor, digest, emissaryData[1:], executions, lockTag);
        }

        // Default case for unsupported modes
        return INVALID_RETURN;
    }

    /* //////////////////////////////////////////////////////////////
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

    /// @notice Returns the EIP-712 domain separator for this contract
    /// @dev Calculates the domain separator based on the domain name, version, chain ID, and
    ///      contract address.
    /// @return The EIP-712 domain separator.
    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return _domainSeparator();
    }

    /// @notice Returns the EIP-712 typed data hash for a given hash without chain ID
    function _getTypedDataHashSansChainId(bytes32 hash)
        internal
        view
        override(EmissaryBase, SmartSessionMixin)
        returns (bytes32)
    {
        return _hashTypedDataSansChainId(hash);
    }
}
