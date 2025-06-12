// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Contracts
import { EmissaryBase } from "@core/EmissaryBase.sol";
import { SmartSessionMixin } from "@core/SmartSessionMixin.sol";
import { CompactEIP712 } from "@compact-utils/common/CompactEIP712.sol";

// Interfaces
import { ISmartSessionEmissary } from "@interfaces/ISmartSessionEmissary.sol";

// Libraries

// Types

/// @title Smart Session Emissary
/// @notice An extended emissary contract that supports multiple verification modes including
///         SmartSessions, stateless validators, and ECDSA/Passkey configurations.
contract SmartSessionEmissary is EmissaryBase, SmartSessionMixin {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    /*//////////////////////////////////////////////////////////////
                               CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @notice Initializes the SmartSessionEmissary contract
    /// @param compact The address of The Compact contract
    constructor(address compact) CompactEIP712(compact) { }

    /*//////////////////////////////////////////////////////////////
                                 CLAIM
    //////////////////////////////////////////////////////////////*/

    /// @notice Verifies claims with mode-based dispatch to appropriate verification method
    /// @param sponsor The sponsor account associated with the claim
    /// @param digest The digest of the claim hash
    /// @param claimHash The hash of the claim to be verified
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
        external
        view
        returns (bytes4)
    {
        // ERC-7739 support detection
        if (digest == 0x7739773977397739773977397739773977397739773977397739773977397739) {
            return bytes4(0x77390001);
        }

        // Extract mode from first byte of emissaryData
        uint8 mode = uint8(emissaryData[0]);

        // Mode-based dispatch for claim verification
        if (mode == 0) {
            // Stateless Validator mode
            return _verifyClaimStatelessValidator(sponsor, digest, emissaryData, lockTag);
        } else if (mode == 1) {
            // ECDSA mode
            return _verifyClaimECDSA(sponsor, digest, emissaryData, lockTag);
        } else if (mode == 2) {
            // Passkey mode
            return _verifyClaimPasskey(sponsor, digest, emissaryData, lockTag);
        } else if (mode == 3) {
            // SmartSession mode
            return _verifyClaimSmartSession(sponsor, claimHash, emissaryData, lockTag);
        }

        // Default case for unsupported modes
        return bytes4(0xFFFFFFFF);
    }

    /*//////////////////////////////////////////////////////////////
                               EXECUTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Validates executions using mode-based dispatch
    /// @param account The account for which the policies are being enforced
    /// @param hash The hash of the user operation
    /// @param emissaryData Data containing mode and mode-specific execution data
    /// @param executions The execution data for the user operation
    /// @return bytes4 The function selector on success, or a specific failure code otherwise
    function verifyExecution(
        address account,
        bytes32 hash,
        bytes calldata emissaryData,
        bytes calldata executions
    )
        external
        returns (bytes4)
    {
        // Extract mode from first byte
        // Mode-based dispatch for execution verification
        return bytes4(0xFFFFFFFF);
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

    /// @notice Returns the EIP-712 domain separator for this contract
    /// @dev Calculates the domain separator based on the domain name, version, chain ID, and
    ///      contract address.
    /// @return The EIP-712 domain separator.
    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return _domainSeparator();
    }
}
