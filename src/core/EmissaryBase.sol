// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Contracts
import { NonceManager } from "@core/NonceManager.sol";
import { StatelessValidation } from "@core/StatelessValidation.sol";

// Interfaces
import { IStatelessValidator } from "@compact-utils/interfaces/IStatelessValidator.sol";
import { ISmartSessionEmissary } from "@interfaces/ISmartSessionEmissary.sol";

// Libraries
import { Compressed } from "@compact-utils/common/CompressedStorageLib.sol";
import { IdLib } from "@the-compact/lib/IdLib.sol";
import { HashLibV2 } from "@lib/HashLibV2.sol";
import { SignatureLib } from "@lib/SignatureLib.sol";
import { LibSort } from "@solady/utils/LibSort.sol";
import { DigestCacheLib } from "@lib/DigestCacheLib.sol";

// Types
import {
    EmissaryConfig,
    EmissaryEnable,
    INVALID_RETURN,
    WebAuthVerificationContext
} from "@types/DataTypes.sol";
import { Execution } from "@smartsessions/lib/ExecutionLib.sol";

/// @title EmissaryBase
/// @notice Base emissary contract providing basic validator functionality (ECDSA, Passkey,
///         Stateless validators)
abstract contract EmissaryBase is StatelessValidation, NonceManager, ISmartSessionEmissary {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using IdLib for *;
    using Compressed for *;
    using SignatureLib for *;
    using DigestCacheLib for *;

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
        public
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
        bytes32 hash = HashLibV2.hashConfig({
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

        // Load configuration
        Compressed.Bytes storage $config =
            $statelessValidatorConfig[account][config.configId][lockTag][config.validator];
        // Check if the configuration is already initialized
        bool isInit = $config.sload().length == 0;

        // Verify user and allocator signatures
        digest.verifySignatures(
            config.allocator, account, enableData.allocatorSig, enableData.userSig, isInit
        );

        // Store configuration
        $config.sstore(config.validatorConfig);

        // Emit configuration update event
        emit EmissaryConfigUpdated(account, config.validator, lockTag);
    }

    /*//////////////////////////////////////////////////////////////
                                 CLAIM
    //////////////////////////////////////////////////////////////*/

    /// @notice Verifies digests using a configured Stateless Validator
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

        // Check if this digest has already been verified in this transaction
        if (digest.isAlreadyVerified(sponsor, validator, configId, lockTag)) {
            return this.verifyClaim.selector;
        }

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

    /// @notice Verifies digests using ECDSA signatures and stored ECDSA configurations
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

        // Check if this digest has already been verified in this transaction
        if (digest.isAlreadyVerified(sponsor, configId, lockTag)) {
            return this.verifyClaim.selector;
        }

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

    /// @notice Verifies digests using Passkey signatures and stored Passkey configurations
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

        // Check if this digest has already been verified in this transaction
        if (digest.isAlreadyVerified(sponsor, configId, lockTag)) {
            return this.verifyClaim.selector;
        }

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
        Execution[] calldata, /* executions */
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

        // Check if this digest has already been verified in this transaction
        if (digest.isAlreadyVerified(sponsor, validator, configId, lockTag)) {
            return this.verifyExecution.selector;
        }

        // Get the compressed configuration data
        Compressed.Bytes storage $config =
            $statelessValidatorConfig[sponsor][configId][lockTag][validator];
        bytes memory configData = $config.sload();

        // Validate the configuration exists
        require(configData.length != 0, InvalidEmissaryConfig());

        // Delegate signature validation to the stateless validator
        bool isValid = validator.validateSignatureWithData(digest, emissaryData, configData);

        // Return the function selector on success, or a specific failure code otherwise.
        if (isValid) {
            // Mark digest as verified in this transaction
            digest.markAsVerified(sponsor, validator, configId, lockTag);
            return this.verifyExecution.selector;
        } else {
            return INVALID_RETURN;
        }
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
        Execution[] calldata, /* executions */
        bytes12 lockTag
    )
        internal
        virtual
        returns (bytes4)
    {
        // Parse emissaryData format for ECDSA:
        uint8 configId = uint8(bytes1(emissaryData[:1]));
        emissaryData = emissaryData[1:];

        // Check if this digest has already been verified in this transaction
        if (digest.isAlreadyVerified(sponsor, configId, lockTag)) {
            return this.verifyExecution.selector;
        }

        // Get the compressed configuration data
        Compressed.Bytes storage $config = $ecdsaPasskeyConfig[sponsor][configId][lockTag];
        bytes memory configData = $config.sload();

        // Validate the configuration exists
        require(configData.length != 0, InvalidEmissaryConfig());

        // Validate the signature using ECDSA
        bool isValid = _validateSignatureWithDataECDSA(digest, emissaryData, configData);

        // Return the function selector on success, or a specific failure code otherwise.
        if (isValid) {
            // Mark digest as verified in this transaction
            digest.markAsVerified(sponsor, configId, lockTag);
            return this.verifyExecution.selector;
        } else {
            return INVALID_RETURN;
        }
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
        Execution[] calldata, /* executions */
        bytes12 lockTag
    )
        internal
        virtual
        returns (bytes4)
    {
        // Parse emissaryData format for Passkey:
        uint8 configId = uint8(bytes1(emissaryData[:1]));
        emissaryData = emissaryData[1:];

        // Check if this digest has already been verified in this transaction
        if (digest.isAlreadyVerified(sponsor, configId, lockTag)) {
            return this.verifyExecution.selector;
        }

        // Get the compressed configuration data
        Compressed.Bytes storage $config = $ecdsaPasskeyConfig[sponsor][configId][lockTag];
        bytes memory configData = $config.sload();

        // Validate the configuration exists
        require(configData.length != 0, InvalidEmissaryConfig());

        // Validate the signature using Passkey
        bool isValid = _validateSignatureWithDataPasskey(digest, emissaryData, configData);

        // Return the function selector on success, or a specific failure code otherwise.
        if (isValid) {
            // Mark digest as verified in this transaction
            digest.markAsVerified(sponsor, configId, lockTag);
            return this.verifyExecution.selector;
        } else {
            return INVALID_RETURN;
        }
    }

    /*//////////////////////////////////////////////////////////////
                                VIRTUAL
    //////////////////////////////////////////////////////////////*/

    /// @notice Returns the typed data hash for a given hash
    function _getTypedDataHashSansChainId(bytes32 hash) internal view virtual returns (bytes32);
}
