// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Contracts
import { NonceManager } from "@core/NonceManager.sol";

// Interfaces
import { IStatelessValidator } from "@compact-utils/interfaces/IStatelessValidator.sol";

// Libraries

// Types
import { EmissaryConfig, EmissaryEnable } from "@interfaces/ISmartSessionEmissary.sol";

/// @title EmissaryBase
/// @notice Base emissary contract providing basic validator functionality (ECDSA, Passkey,
///         Stateless validators)
abstract contract EmissaryBase is NonceManager, EIP712, CompactEIP712 {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

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
    ) public statelessValidatorConfig;

    /// @notice Emissary storage for ECDSA/Passkey configurations
    /// @dev Maps sponsor => configId => lockTag => compressed config data
    mapping(
        address sponsor => mapping(uint8 configId => mapping(bytes12 lockTag => Compressed.Bytes))
    ) public ecdsaPasskeyConfig;

    /*//////////////////////////////////////////////////////////////
                               CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address compact) CompactEIP712(compact) { }

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
        // bytes12 lockTag = config.allocator.usingAllocatorId().toLockTag(config.scope,
        // config.resetPeriod);

        // Nonce validation to prevent replay attacks
        // - Get current nonce for account + lockTag
        // - Require enableData.nonce > currentNonce
        // - Update stored nonce

        // Security validations
        // - Verify chain ID matches current chain
        // - Verify enableData.expires > block.timestamp
        // - Calculate EIP-712 hash for configuration
        // - Verify user signature (if msg.sender != account)
        // - Verify allocator signature

        // Store configuration based on mode
        // if (config.mode == 0 || config.mode == 1) {
        //     // Store in ecdsaPasskeyConfig[account][configId][lockTag]
        // } else if (config.validator != address(0)) {
        //     // Store in statelessValidatorConfig[account][configId][lockTag][validator]
        // }

        //  Emit configuration update event
    }

    /*//////////////////////////////////////////////////////////////
                                 VERIFY
    //////////////////////////////////////////////////////////////*/

    /// @notice Verifies claims using basic methods (ECDSA, Passkey, Stateless validators)
    /// @param sponsor The sponsor account associated with the claim
    /// @param digest The hash of the claim being verified
    /// @param emissaryData Data containing the mode, configId, and signature data
    /// @param lockTag The lock tag associated with the configuration
    /// @return The selector if valid, otherwise 0xFFFFFFFF
    function _verifyClaimBase(
        address sponsor,
        bytes32 digest,
        bytes calldata emissaryData,
        bytes12 lockTag
    )
        internal
        view
        virtual
        returns (bytes4)
    {
        // Parse emissaryData format:
        // For ECDSA/Passkey (mode 0/1): [mode: 1 byte][configId: 1 byte][signature: remaining]
        // For Stateless: [mode: 1 byte][configId: 1 byte][validator: 20 bytes][signature:
        // remaining]

        // Load appropriate configuration from storage
        // - For mode 0/1: ecdsaPasskeyConfig[sponsor][configId][lockTag]
        // - For stateless: statelessValidatorConfig[sponsor][configId][lockTag][validator]

        // Validate configuration exists (non-zero length)

        // Perform mode-specific signature validation
        // - Mode 0: ECDSA signature verification
        // - Mode 1: Passkey signature verification
        // - Other: Delegate to stateless validator.validateSignatureWithData()

        // Return success selector or failure (0xFFFFFFFF)
        return bytes4(0xFFFFFFFF);
    }

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
        external
        virtual
        onlyWhitelistedSource
        returns (bytes4)
    { }

    /*//////////////////////////////////////////////////////////////
                                  712
    //////////////////////////////////////////////////////////////*/

    /// @notice Returns the EIP-712 domain name and version
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
}
