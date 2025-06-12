// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Contracts
import { NonceManager } from "@core/NonceManager.sol";
import { EIP712 } from "@solady/utils/EIP712.sol";
import { CompactEIP712 } from "@compact-utils/common/CompactEIP712.sol";

// Interfaces
import { IStatelessValidator } from "@compact-utils/interfaces/IStatelessValidator.sol";
import { ISmartSessionEmissary } from "@interfaces/ISmartSessionEmissary.sol";

// Libraries
import { Compressed } from "@compact-utils/common/CompressedStorageLib.sol";
import { IdLib } from "@the-compact/lib/IdLib.sol";
import { EIP712Hash } from "@lib/EIP712Hash.sol";
import { SignatureCheckerLib } from "@solady/utils/SignatureCheckerLib.sol";

// Types
import { EmissaryConfig, EmissaryEnable } from "@types/DataTypes.sol";

/// @title EmissaryBase
/// @notice Base emissary contract providing basic validator functionality (ECDSA, Passkey,
///         Stateless validators)
abstract contract EmissaryBase is NonceManager, EIP712, CompactEIP712, ISmartSessionEmissary {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using IdLib for address;
    using IdLib for bytes12;
    using IdLib for uint96;
    using SignatureCheckerLib for address;
    using Compressed for Compressed.Bytes;

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
        uint256 nonce = enableData.nonce;
        uint256 currentNonce = $emissaryNonce[account][lockTag];
        require(nonce > currentNonce, InvalidNonce());
        $emissaryNonce[account][lockTag] = nonce;

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
        bytes32 digest = _hashTypedDataSansChainId(hash);

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

    /// @notice Verifies claims using Stateless validator configuration
    /// @param sponsor The sponsor account associated with the claim
    /// @param digest The hash of the claim being verified
    /// @param emissaryData Data containing the mode, configId, and signature data
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
            : bytes4(0xFFFFFFFF);
    }

    function _verifyClaimECDSA(
        address sponsor,
        bytes32 digest,
        bytes calldata emissaryData,
        bytes12 lockTag
    )
        internal
        view
        returns (bytes4)
    { }

    function _verifyClaimPasskey(
        address sponsor,
        bytes32 digest,
        bytes calldata emissaryData,
        bytes12 lockTag
    )
        internal
        view
        returns (bytes4)
    { }

    /*//////////////////////////////////////////////////////////////
                               EXECUTION
    //////////////////////////////////////////////////////////////*/

    /// @notice Validates executions for an account using basic methods (ECDSA, Passkey,
    ///         Stateless validators)
    /// @param account The account for which the executions are being verified
    /// @param hash The hash of the user operation
    /// @param emissaryData data containing mode, configId, and signature data
    /// @param executions The execution data for the user operation
    /// @return bytes4 The function selector on success, or a specific failure code otherwise
    function _verifyExecutionBase(
        address account,
        bytes32 hash,
        bytes calldata emissaryData,
        bytes calldata executions
    )
        internal
        virtual
        returns (bytes4)
    { }
}
