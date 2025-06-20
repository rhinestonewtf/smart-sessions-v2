// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Contracts
import { NonceManager } from "@core/NonceManager.sol";

// Interfaces
import { IStatelessValidator } from "@compact-utils/interfaces/IStatelessValidator.sol";
import { ISmartSessionEmissary } from "@interfaces/ISmartSessionEmissary.sol";

// Libraries
import { Compressed } from "@compact-utils/common/CompressedStorageLib.sol";
import { IdLib } from "@the-compact/lib/IdLib.sol";
import { EIP712Hash } from "@lib/EIP712Hash.sol";
import { SignatureCheckerLib } from "@solady/utils/SignatureCheckerLib.sol";
import { CheckSignatures } from "@checknsignatures/CheckNSignatures.sol";
import { ECDSA } from "@solady/utils/ECDSA.sol";
import { WebAuthn } from "@webauthn/WebAuthn.sol";
import { LibSort } from "@solady/utils/LibSort.sol";

// Types
import {
    EmissaryConfig,
    EmissaryEnable,
    INVALID_RETURN,
    WebAuthVerificationContext
} from "@types/DataTypes.sol";

/// @title EmissaryBase
/// @notice Base emissary contract providing basic validator functionality (ECDSA, Passkey,
///         Stateless validators)
abstract contract EmissaryBase is NonceManager, ISmartSessionEmissary {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using IdLib for address;
    using IdLib for bytes12;
    using IdLib for uint96;
    using SignatureCheckerLib for address;
    using Compressed for Compressed.Bytes;
    using LibSort for *;

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Emissary storage for stateless validator configurations
    /// @dev Maps sponsor => configId => lockTag => validator => compressed config data
    mapping(
        address sponsor
            => mapping(
                uint8 configId
                    => mapping(
                        bytes12 lockTag
                            => mapping(IStatelessValidator validator => Compressed.Bytes)
                    )
            )
    ) public $statelessValidatorConfig;

    /// @notice Emissary storage for ECDSA/Passkey configurations
    /// @dev Maps sponsor => configId => lockTag => compressed config data
    mapping(
        address sponsor => mapping(uint8 configId => mapping(bytes12 lockTag => Compressed.Bytes))
    ) public $ecdsaPasskeyConfig;

    /*//////////////////////////////////////////////////////////////
                                 CONFIG
    //////////////////////////////////////////////////////////////*/

    /// @notice Sets the vanilla Emissary configuration for a specific account
    /// @param account The address of the account for which the configuration is being set
    /// @param config The Emissary configuration
    /// @param enableData The Emissary enable data
    function setConfig(
        address account,
        EmissaryConfig calldata config,
        EmissaryEnable calldata enableData
    )
        external
        virtual
    {
        // Derive lockTag from allocator, scope, resetPeriod
        bytes12 lockTag =
            config.allocator.toAllocatorId().toLockTag(config.scope, config.resetPeriod);

        // Nonce validation to prevent replay attacks
        uint256 nonce = $emissaryNonce[account][lockTag]++;

        // Verify chain ID matches current chain
        require(
            enableData.allChainIds[enableData.chainIndex] == block.chainid,
            InvalidEmissaryEnableData()
        );

        // Verify data expires after current block timestamp
        require(enableData.expires > block.timestamp, InvalidEmissaryEnableData());

        // Calculate EIP-712 hash for configuration
        bytes32 hash = EIP712Hash.config({
            sponsor: account,
            validator: config.validator,
            configId: config.configId,
            lockTag: lockTag,
            expires: enableData.expires,
            nonce: nonce,
            validatorConfig: config.validatorConfig,
            chainIds: enableData.allChainIds
        });
        // Hash the typed data structure (excluding chainId as it's implicitly checked)
        bytes32 digest = _getTypedDataHashSansChainId(hash);

        // Check if config is initialized
        Compressed.Bytes storage $config =
            $statelessValidatorConfig[account][config.configId][lockTag][config.validator];
        bool isInit = $config.sload().length == 0;

        // Store configuration
        $config.sstore(config.validatorConfig);

        // If already initialized, verify signatures
        if (!isInit) {
            // Verify user signature
            if (msg.sender != account) {
                require(
                    account.isValidSignatureNowCalldata(digest, enableData.userSig),
                    InvalidUserSignature()
                );
            }
            // Verify allocator signature
            require(
                config.allocator.isValidERC1271SignatureNowCalldata(digest, enableData.allocatorSig),
                InvalidAllocatorSignature()
            );
        }

        // Emit configuration update event
        emit EmissaryConfigUpdated(account, config.validator, lockTag);
    }

    /*//////////////////////////////////////////////////////////////
                                 CLAIM
    //////////////////////////////////////////////////////////////*/

    /// @notice Verifies claims using a configured Stateless Validator
    /// @param sponsor The sponsor account associated with the claim
    /// @param digest The hash of the claim being verified
    /// @param emissaryData Data containing validator address, configId, and signature
    /// @param lockTag The lock tag associated with the configuration
    /// @return The selector if valid, otherwise 0xFFFFFFFF
    function _verifyClaimStatelessValidator(
        address sponsor,
        bytes32 digest,
        bytes calldata emissaryData,
        bytes12 lockTag
    )
        internal
        view
        returns (bytes4)
    {
        // Parse emissaryData format for Stateless Validator:
        IStatelessValidator validator = IStatelessValidator(address(bytes20(emissaryData[:20])));
        uint8 configId = uint8(bytes1(emissaryData[20:21]));
        emissaryData = emissaryData[21:];

        // Get the compressed configuration data
        Compressed.Bytes storage $config =
            $statelessValidatorConfig[sponsor][configId][lockTag][validator];
        bytes memory configData = $config.sload();

        // Validate the configuration exists
        require(configData.length != 0, InvalidEmissaryConfig());

        // Delegate signature validation to the stateless validator
        // Return the function selector on success, or a specific failure code otherwise.
        return validator.validateSignatureWithData(digest, emissaryData, configData)
            ? this.verifyClaim.selector
            : INVALID_RETURN;
    }

    /// @notice Verifies claims using ECDSA signatures and stored ECDSA configurations
    /// @param sponsor The sponsor account associated with the claim
    /// @param digest The hash of the claim being verified
    /// @param emissaryData Data containing mode byte and mode-specific verification data
    /// @param lockTag The lock tag associated with the configuration
    function _verifyClaimECDSA(
        address sponsor,
        bytes32 digest,
        bytes calldata emissaryData,
        bytes12 lockTag
    )
        internal
        view
        returns (bytes4)
    {
        // Parse emissaryData format for ECDSA:
        uint8 configId = uint8(bytes1(emissaryData[:1]));
        emissaryData = emissaryData[1:];

        // Get the compressed configuration data
        Compressed.Bytes storage $config = $ecdsaPasskeyConfig[sponsor][configId][lockTag];
        bytes memory configData = $config.sload();

        // Validate the configuration exists
        require(configData.length != 0, InvalidEmissaryConfig());

        // Validate the signature using ECDSA
        bool isValid = _validateSignatureWithDataECDSA(digest, emissaryData, configData);

        // Return the function selector on success, or a specific failure code otherwise.
        return isValid ? this.verifyClaim.selector : INVALID_RETURN;
    }

    /// @notice Verifies claims using Passkey signatures and stored Passkey configurations
    /// @param sponsor The sponsor account associated with the claim
    /// @param digest The hash of the claim being verified
    /// @param emissaryData Data containing mode byte and mode-specific verification data
    /// @param lockTag The lock tag associated with the configuration
    /// @return The selector if valid, otherwise 0xFFFFFFFF
    function _verifyClaimPasskey(
        address sponsor,
        bytes32 digest,
        bytes calldata emissaryData,
        bytes12 lockTag
    )
        internal
        view
        returns (bytes4)
    {
        // Parse emissaryData format for Passkey:
        uint8 configId = uint8(bytes1(emissaryData[:1]));
        emissaryData = emissaryData[1:];

        // Get the compressed configuration data
        Compressed.Bytes storage $config = $ecdsaPasskeyConfig[sponsor][configId][lockTag];
        bytes memory configData = $config.sload();

        // Validate the configuration exists
        require(configData.length != 0, InvalidEmissaryConfig());

        // Validate the signature using Passkey
        bool isValid = _validateSignatureWithDataPasskey(digest, emissaryData, configData);

        // Return the function selector on success, or a specific failure code otherwise.
        return isValid ? this.verifyClaim.selector : INVALID_RETURN;
    }

    /*//////////////////////////////////////////////////////////////
                               EXECUTION
    //////////////////////////////////////////////////////////////*/

    /// @notice Validates executions for an account using a configured Stateless Validator
    /// @param sponsor The account for which the executions are being verified
    /// @param digest The hash of the user operation
    /// @param emissaryData data containing validator address, configId, lockTag, and signature
    /// @param lockTag The lock tag associated with the configuration
    /// @return bytes4 The function selector on success, or a specific failure code otherwise
    function _verifyExecutionStatelessValidator(
        address sponsor,
        bytes32 digest,
        bytes calldata emissaryData,
        bytes calldata, /* executions */
        bytes12 lockTag
    )
        internal
        virtual
        returns (bytes4)
    {
        // Parse emissaryData format for Stateless Validator:
        IStatelessValidator validator = IStatelessValidator(address(bytes20(emissaryData[:20])));
        uint8 configId = uint8(bytes1(emissaryData[20:21]));
        emissaryData = emissaryData[21:];

        // Get the compressed configuration data
        Compressed.Bytes storage $config =
            $statelessValidatorConfig[sponsor][configId][lockTag][validator];
        bytes memory configData = $config.sload();

        // Validate the configuration exists
        require(configData.length != 0, InvalidEmissaryConfig());

        // Delegate signature validation to the stateless validator
        // Return the function selector on success, or a specific failure code otherwise.
        return validator.validateSignatureWithData(digest, emissaryData, configData)
            ? this.verifyClaim.selector
            : INVALID_RETURN;
    }

    /// @notice Validates executions for an account using ECDSA signatures and stored ECDSA
    /// configurations
    /// @param sponsor The account for which the executions are being verified
    /// @param digest The hash of the user operation
    /// @param emissaryData Data containing mode byte and mode-specific execution data
    /// @return bytes4 The function selector on success, or a specific failure code otherwise
    function _verifyExecutionECDSA(
        address sponsor,
        bytes32 digest,
        bytes calldata emissaryData,
        bytes calldata, /* executions */
        bytes12 /* lockTag */
    )
        internal
        virtual
        returns (bytes4)
    {
        // Parse emissaryData format for ECDSA:
        uint8 configId = uint8(bytes1(emissaryData[:1]));
        emissaryData = emissaryData[1:];

        // Get the compressed configuration data
        Compressed.Bytes storage $config = $ecdsaPasskeyConfig[sponsor][configId][bytes12(0)];
        bytes memory configData = $config.sload();

        // Validate the configuration exists
        require(configData.length != 0, InvalidEmissaryConfig());

        // Validate the signature using ECDSA
        bool isValid = _validateSignatureWithDataECDSA(digest, emissaryData, configData);

        // Return the function selector on success, or a specific failure code otherwise.
        return isValid ? this.verifyClaim.selector : INVALID_RETURN;
    }

    /// @notice Validates executions for an account using Passkey signatures and stored Passkey
    ///         configurations
    /// @param sponsor The account for which the executions are being verified
    /// @param digest The hash of the user operation
    /// @param emissaryData Data containing mode byte and mode-specific execution data
    /// @return bytes4 The function selector on success, or a specific failure code otherwise
    function _verifyExecutionPasskey(
        address sponsor,
        bytes32 digest,
        bytes calldata emissaryData,
        bytes calldata, /* executions */
        bytes12 /* lockTag */
    )
        internal
        virtual
        returns (bytes4)
    {
        // Parse emissaryData format for Passkey:
        uint8 configId = uint8(bytes1(emissaryData[:1]));
        emissaryData = emissaryData[1:];

        // Get the compressed configuration data
        Compressed.Bytes storage $config = $ecdsaPasskeyConfig[sponsor][configId][bytes12(0)];
        bytes memory configData = $config.sload();

        // Validate the configuration exists
        require(configData.length != 0, InvalidEmissaryConfig());

        // Validate the signature using Passkey
        bool isValid = _validateSignatureWithDataPasskey(digest, emissaryData, configData);

        // Return the function selector on success, or a specific failure code otherwise.
        return isValid ? this.verifyClaim.selector : INVALID_RETURN;
    }

    /*//////////////////////////////////////////////////////////////
                                 ECDSA
    //////////////////////////////////////////////////////////////*/

    /// @notice Validates a signature against a hash and data using ECDSA
    function _validateSignatureWithDataECDSA(
        bytes32 hash,
        bytes calldata signature,
        bytes memory data
    )
        internal
        view
        returns (bool)
    {
        // decode the threshold and owners
        (uint256 _threshold, address[] memory _owners) = abi.decode(data, (uint256, address[]));

        // check that owners are sorted and uniquified
        if (!_owners.isSortedAndUniquified()) {
            return false;
        }

        // check that threshold is set
        if (_threshold == 0) {
            return false;
        }

        // recover the signers from the signatures
        address[] memory signers = CheckSignatures.recoverNSignatures(
            ECDSA.toEthSignedMessageHash(hash), signature, _threshold
        );

        // sort and uniquify the signers to make sure a signer is not reused
        signers.sort();
        signers.uniquifySorted();

        // check if the signers are owners
        uint256 validSigners;
        uint256 signersLength = signers.length;
        for (uint256 i = 0; i < signersLength; i++) {
            (bool found,) = _owners.searchSorted(signers[i]);
            if (found) {
                validSigners++;
            }
        }

        // check if the threshold is met and return the result
        if (validSigners >= _threshold) {
            // if the threshold is met, return true
            return true;
        }
        // if the threshold is not met, return false
        return false;
    }

    /*//////////////////////////////////////////////////////////////
                                PASSKEY
    //////////////////////////////////////////////////////////////*/

    /// @notice Validates a signature with external credential data
    /// @dev Used for stateless validation without pre-registered credentials
    /// @param hash Hash of the data to validate
    /// @param signature WebAuthn signature data
    /// @param data Encoded credential details and threshold
    /// @return bool True if the signature is valid, false otherwise
    function _validateSignatureWithDataPasskey(
        bytes32 hash,
        bytes calldata signature,
        bytes memory data
    )
        internal
        view
        returns (bool)
    {
        // Decode the threshold and credentials
        WebAuthVerificationContext memory context = abi.decode(data, (WebAuthVerificationContext));
        // Make sure the credentials are unique and sorted
        context.credentialIds.sort();
        context.credentialIds.uniquifySorted();

        // Decode signature
        // Format: abi.encode(WebAuthn.WebAuthnAuth[])
        WebAuthn.WebAuthnAuth[] memory auth = abi.decode(signature, (WebAuthn.WebAuthnAuth[]));

        // Check that arrays have matching lengths
        uint256 credentialsLength = context.credentialIds.length;
        if (credentialsLength != context.credentialData.length) {
            return false;
        }

        // Check that threshold is valid
        if (context.threshold == 0 || context.threshold > credentialsLength) {
            return false;
        }

        // Cache lengths
        uint256 sigCount = auth.length;

        // Check number of signatures
        if (sigCount == 0 || sigCount < context.threshold) {
            return false;
        }

        // Track valid signatures
        uint256 validCount;

        // Verify each signature
        for (uint256 i; i < sigCount; ++i) {
            // Challenge is the hash to be signed
            bytes memory challenge = abi.encode(hash);

            // IMPORTANT:
            // **********************************************************************
            // * We assume here that signatures are ordered to match credential IDs *
            // **********************************************************************

            // Verify the signature against the credential at the same index
            bool valid = WebAuthn.verify(
                challenge,
                context.credentialData[i].requireUV,
                auth[i],
                context.credentialData[i].pubKeyX,
                context.credentialData[i].pubKeyY,
                context.usePrecompile
            );

            if (valid) {
                ++validCount;

                // Early return if threshold is met
                if (validCount >= context.threshold) {
                    return true;
                }
            }
        }

        // If we reach this, we didn't meet the threshold
        return false;
    }

    /*//////////////////////////////////////////////////////////////
                                VIRTUAL
    //////////////////////////////////////////////////////////////*/

    /// @notice Returns the typed data hash for a given hash
    function _getTypedDataHashSansChainId(bytes32 hash) internal view virtual returns (bytes32);
}
