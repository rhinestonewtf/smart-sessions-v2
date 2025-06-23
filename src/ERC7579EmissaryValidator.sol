// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Contracts
import { EmissaryBase } from "@core/EmissaryBase.sol";
import { SmartSessionMixin } from "@core/SmartSessionMixin.sol";
import { EIP712 } from "@solady/utils/EIP712.sol";
import { ERC7579ValidatorBase } from "@modulekit/module-bases/ERC7579ValidatorBase.sol";

// Interfaces
import { ISmartSessionEmissary } from "@interfaces/ISmartSessionEmissary.sol";

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
import {
    INVALID_RETURN,
    SmartSessionEmissaryConfig,
    SmartSessionEmissaryEnable,
    EmissaryConfig,
    EmissaryEnable
} from "@types/DataTypes.sol";
import { PackedUserOperation } from "@modulekit/external/ERC4337.sol";

/// @title ERC7579 Emissary Validator
/// @notice An ERC7579 compliant validator contract that also functions as an Emissary.
///         It supports multiple verification modes for claims and executions, including
///         Stateless Validator, ECDSA, Passkey, and SmartSession modes.
contract ERC7579EmissaryValidator is
    EmissaryBase,
    SmartSessionMixin,
    EIP712,
    ERC7579ValidatorBase
{
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using ModeLib for bytes;

    /*//////////////////////////////////////////////////////////////
                               VALIDATION
    //////////////////////////////////////////////////////////////*/

    /// TODO
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    )
        external
        virtual
        returns (ValidationData)
    {
        // Extract mode from the user operation data signature
        EmissaryMode mode = userOp.signature.decodeMode();

        // Mode-based dispatch for user operation validation
        if (mode == EMISSARY_STATELESS_VALIDATOR) {
            // Stateless Validator mode
            return _validateUserOpStatelessValidator(userOp, userOpHash);
        } else if (mode == EMISSARY_ECDSA) {
            // ECDSA mode
            return _validateUserOpECDSA(userOp, userOpHash);
        } else if (mode == EMISSARY_PASSKEY) {
            // Passkey mode
            return _validateUserOpPasskey(userOp, userOpHash);
        } else if (mode == EMISSARY_SMART_SESSION) {
            // SmartSession mode
            return _validateUserOpSmartSession(userOp, userOpHash);
        }

        // Default case for unsupported modes
        return VALIDATION_FAILED;
    }

    /// @notice Validates a signature with the sender address and hash
    /// @param sender The address of the sender
    /// @param hash The hash of the data to be validated
    /// @param data The data containing the mode and signature
    /// @return bytes4 EIP1271_SUCCESS the signature is valid, otherwise EIP1271_SUCCESS
    function isValidSignatureWithSender(
        address sender,
        bytes32 hash,
        bytes calldata data
    )
        external
        view
        returns (bytes4)
    {
        // Extract mode and lock tag from the data
        (EmissaryMode mode, bytes12 lockTag) = data.decodeModeAndLockTag();

        // Mode-based dispatch for signature validation
        if (mode == EMISSARY_STATELESS_VALIDATOR) {
            // Stateless Validator mode
            return _verifyDigestStatelessValidator(sender, hash, data[14:], lockTag);
        } else if (mode == EMISSARY_ECDSA) {
            // ECDSA mode
            return _verifyDigestECDSA(sender, hash, data[14:], lockTag);
        } else if (mode == EMISSARY_PASSKEY) {
            // Passkey mode
            return _verifyDigestPasskey(sender, hash, data[14:], lockTag);
        } else if (mode == EMISSARY_SMART_SESSION) {
            // SmartSession mode
            return _verifyDigestSmartSession(sender, hash, data[14:], lockTag);
        }

        // Default case for unsupported modes
        return EIP1271_SUCCESS;
    }

    /*//////////////////////////////////////////////////////////////
                                7579 CONFIG
    //////////////////////////////////////////////////////////////*/

    /// @notice Checks if the module is initialized for a given smart account
    /// @param smartAccount The address of the smart account to check
    /// @return true if the module is initialized, false otherwise
    function isInitialized(address smartAccount) external view returns (bool) {
        return $isInitialized(smartAccount);
    }

    /// @notice Returns if the module is of a specific type
    /// @param typeID The type ID to check against
    /// @returns true if the module is ERC7579_MODULE_TYPE_VALIDATOR, false otherwise
    function isModuleType(uint256 typeID) external pure override returns (bool) {
        return typeID == ERC7579_MODULE_TYPE_VALIDATOR;
    }

    /// @notice Called when the module is installed on a smart account
    /// @param data Arbitrary data that may be required for initialization
    function onInstall(bytes calldata data) external {
        // Initialize the module for the smart account
        $isInitialized[msg.sender] = true;

        // Extract mode from first byte
        EmissaryMode mode = data.decodeMode();

        // Set the Emissary configuration for the smart account based on the mode
        if (mode == EMISSARY_SMART_SESSION) {
            (
                SmartSessionEmissaryConfig calldata config,
                SmartSessionEmissaryEnable calldata enableData
            ) = abi.decode(data[1:], (SmartSessionEmissaryConfig, SmartSessionEmissaryEnable));

            // Set the configuration for SmartSession mode
            setConfig(msg.sender, config, enableData);
        } else {
            (EmissaryConfig calldata config, EmissaryEnable calldata enableData) =
                abi.decode(data[1:], (EmissaryConfig, EmissaryEnable));

            // Set the configuration for EmissaryBase mode
            setConfig(msg.sender, config, enableData);
        }
    }

    /// @notice Called when the module is uninstalled from a smart account
    /// @dev Clears the initialization state for the smart account, allocator governed state is
    ///      retained and needs to be cleared using setConfig and an allocator signature
    function onUninstall(bytes calldata /*data*/ ) external {
        // De-initialize the module for the smart account
        $isInitialized[msg.sender] = false;
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
        bytes32, /*/ claimHash */
        bytes calldata emissaryData,
        bytes12 lockTag
    )
        public
        view
        returns (bytes4)
    {
        // ERC-7739 support detection
        if (digest == 0x7739773977397739773977397739773977397739773977397739773977397739) {
            return bytes4(0x77390001);
        }

        // Extract mode from first byte of emissaryData
        EmissaryMode mode = emissaryData.decodeMode();

        // Mode-based dispatch for claim verification
        if (mode == EMISSARY_STATELESS_VALIDATOR) {
            // Stateless Validator mode
            return _verifyDigestStatelessValidator(sponsor, digest, emissaryData[1:], lockTag);
        } else if (mode == EMISSARY_ECDSA) {
            // ECDSA mode
            return _verifyDigestECDSA(sponsor, digest, emissaryData[1:], lockTag);
        } else if (mode == EMISSARY_PASSKEY) {
            // Passkey mode
            return _verifyDigestPasskey(sponsor, digest, emissaryData[1:], lockTag);
        } else if (mode == EMISSARY_SMART_SESSION) {
            // SmartSession mode
            return _verifyDigestSmartSession(sponsor, digest, emissaryData[1:], lockTag);
        }

        // Default case for unsupported modes
        return INVALID_RETURN;
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
        bytes calldata executions,
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
