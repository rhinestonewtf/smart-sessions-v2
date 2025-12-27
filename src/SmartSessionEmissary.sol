// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

// Contracts
import { Emissary as VanillaEmissary } from "@compact-utils/emissary/Emissary.sol";
import { SmartSessionMixin } from "@core/SmartSessionMixin.sol";

// Interfaces
import { ISmartSessionEmissary } from "@interfaces/ISmartSessionEmissary.sol";

// Libraries
import {
    ModeLib,
    EmissaryMode,
    SignatureMode,
    EMISSARY_VANILLA,
    EMISSARY_SMART_SESSION,
    IS_VALID_SIG_1271,
    IS_VALID_SIG_1271_7739
} from "@lib/ModeLib.sol";

// Types
import { INVALID_SIGNATURE } from "@types/DataTypes.sol";
import { Types } from "@rhinestone/compact-utils/src/types/OrderTypes.sol";

// forgefmt: disable-start
///
///    ███████╗███╗   ███╗ █████╗ ██████╗ ████████╗
///    ██╔════╝████╗ ████║██╔══██╗██╔══██╗╚══██╔══╝
///    ███████╗██╔████╔██║███████║██████╔╝   ██║
///    ╚════██║██║╚██╔╝██║██╔══██║██╔══██╗   ██║
///    ███████║██║ ╚═╝ ██║██║  ██║██║  ██║   ██║
///    ╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝
///    ███████╗███████╗███████╗███████╗██╗ ██████╗ ███╗   ██╗
///    ██╔════╝██╔════╝██╔════╝██╔════╝██║██╔═══██╗████╗  ██║
///    ███████╗█████╗  ███████╗███████╗██║██║   ██║██╔██╗ ██║
///    ╚════██║██╔══╝  ╚════██║╚════██║██║██║   ██║██║╚██╗██║
///    ███████║███████╗███████║███████║██║╚██████╔╝██║ ╚████║
///    ╚══════╝╚══════╝╚══════╝╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝
///    ███████╗███╗   ███╗██╗███████╗███████╗ █████╗ ██████╗ ██╗   ██╗
///    ██╔════╝████╗ ████║██║██╔════╝██╔════╝██╔══██╗██╔══██╗╚██╗ ██╔╝
///    █████╗  ██╔████╔██║██║███████╗███████╗███████║██████╔╝ ╚████╔╝
///    ██╔══╝  ██║╚██╔╝██║██║╚════██║╚════██║██╔══██║██╔══██╗  ╚██╔╝
///    ███████╗██║ ╚═╝ ██║██║███████║███████║██║  ██║██║  ██║   ██║
///    ╚══════╝╚═╝     ╚═╝╚═╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝
///
/// @title SmartSessionEmissary
/// @author Rhinestone
/// @notice A 7579 1271 validator that also serves as an emissary supporting both vanilla and
///         Smart Session signature verification and execution validation.
// forgefmt: disable-end
contract SmartSessionEmissary is VanillaEmissary, SmartSessionMixin {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    /// @dev Used to decode emissary mode from emissary data
    using ModeLib for bytes;

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Address of the Intent Executor contract
    address public immutable INTENT_EXECUTOR;

    /// @notice Address of the SmartSessionLens contract for view functions
    address public immutable LENS;

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @notice Constructor to initialize the Smart Session Emissary
    /// @param intentExecutor The address of the Intent Executor contract
    /// @param lens The address of the SmartSessionLens contract for view function delegation
    constructor(address intentExecutor, address lens) {
        INTENT_EXECUTOR = intentExecutor;
        LENS = lens;
    }

    /*//////////////////////////////////////////////////////////////
                               MODIFIERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Modifier to restrict access to only Intent Executor
    modifier onlyIntentExecutor() {
        require(msg.sender == INTENT_EXECUTOR, UnauthorizedSource());
        _;
    }

    /*//////////////////////////////////////////////////////////////
                                  1271
    //////////////////////////////////////////////////////////////*/

    /// @notice Session based ERC-1271 signature validation with mode-based dispatch
    /// @dev Implements ERC-1271 forwarding as defined by ERC-7579. Sessions can sign messages
    ///      and validate ERC-1271 on behalf of smart accounts. Supports two validation modes:
    ///
    ///      Mode 0x00 (IS_VALID_SIG_1271) - Direct validation:
    ///        Signature format: [mode (1)] [permissionId (32)] [policyDataOffset (32)]
    ///                          [validatorSig (variable)] [policyData (variable)]
    ///        Hash is bound to account via: ECDSA.toEthSignedMessageHash(abi.encode(account, hash))
    ///
    ///      Mode 0x01 (IS_VALID_SIG_1271_7739) - ERC-7739 nested EIP-712 validation:
    ///        Signature format: [mode (1)] [permissionId (32)] [policyDataOffset (32)]
    ///                          [validatorSig (variable)] [policyData (variable)]
    ///                          [appDomainSeparator (32)] [contentHash (32)]
    ///                          [contentsDescription (variable)]
    ///                          [uint16(contentsDescription.length)]
    ///        Validates typed data signatures with app-specific domain separation
    ///
    /// @param sender The address of the smart account (ERC-1271 sender)
    /// @param hash The hash of the message to validate
    /// @param signature Mode byte followed by mode-specific signature data
    /// @return result EIP-1271 magic value (0x1626ba7e) on success, 0xffffffff on failure
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

        // Unwrap ERC-6492 if present
        signature = _erc1271UnwrapSignature(signature);

        // Decode mode from first byte
        SignatureMode mode = signature.decodeSignatureMode();

        // Get the actual signature without mode byte
        bytes calldata actualSignature = signature[1:];

        // If mode is unrecognized, success is false by default
        bool success;
        if (mode == IS_VALID_SIG_1271) {
            // IS_VALID_SIG_1271 mode uses direct validation without ERC-7739 wrapping
            success = _erc1271IsValidSignatureNowCalldata({
                sender: sender, // The address of ERC-1271 sender
                hash: hash, // The hash of the message
                signature: actualSignature, // The signature without mode byte
                appDomainSeparator: bytes32(0), // No app domain separator
                contents: signature[0:0] // No additional contents
            });
        } else if (mode == IS_VALID_SIG_1271_7739) {
            // IS_VALID_SIG_1271_7739 mode uses nested EIP-712 validation with ERC-7739 wrapping
            success = _erc1271IsValidSignatureViaNestedEIP712({
                sender: sender, hash: hash, signature: actualSignature
            });
        }

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
        bytes32, // claimHash
        bytes calldata emissaryData,
        bytes12 lockTag
    )
        public
        view
        override(VanillaEmissary, ISmartSessionEmissary)
        returns (bytes4)
    {
        // Extract mode from first byte of emissaryData
        EmissaryMode mode = emissaryData.decodeEmissaryMode();

        // Get the actual emissary data without mode byte
        bytes calldata actualEmissaryData = emissaryData[1:];

        // Mode-based dispatch for claim verification
        if (mode == EMISSARY_VANILLA) {
            // Validate using vanilla emissary signature validation
            return _validateSignature({
                sponsor: sponsor, digest: digest, emissaryData: actualEmissaryData, lockTag: lockTag
            })
                ? this.verifyClaim.selector
                : INVALID_SIGNATURE;
        } else if (mode == EMISSARY_SMART_SESSION) {
            // Validate using SmartSession verification
            return _verifyClaimSmartSession({
                sponsor: sponsor, digest: digest, emissaryData: actualEmissaryData, lockTag: lockTag
            });
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
    /// @return bytes4 The function selector on success, or a specific failure code otherwise
    function verifyExecution(
        address sponsor,
        bytes32 digest,
        bytes calldata emissaryData,
        Types.Operation calldata executions
    )
        public
        onlyIntentExecutor
        returns (bytes4)
    {
        return _verifyExecutionSmartSession({
            account: sponsor, digest: digest, emissaryData: emissaryData, executions: executions
        });
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
        version = "1.0.0";
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

    /*//////////////////////////////////////////////////////////////
                                FALLBACK
    //////////////////////////////////////////////////////////////*/

    /// @notice Delegates unknown function calls to the LENS contract
    /// @dev Enables view functions and nonce management without bloating main contract bytecode
    // solhint-disable-next-line no-complex-fallback
    fallback() external {
        address lens = LENS;
        assembly {
            // Copy calldata to memory
            calldatacopy(0x00, 0x00, calldatasize())

            // Delegatecall to lens
            let result := delegatecall(gas(), lens, 0x00, calldatasize(), 0x00, 0x00)

            // Copy returndata to memory
            returndatacopy(0x00, 0x00, returndatasize())

            // Return or revert based on result
            switch result
            case 0 { revert(0x00, returndatasize()) }
            default { return(0x00, returndatasize()) }
        }
    }
}
