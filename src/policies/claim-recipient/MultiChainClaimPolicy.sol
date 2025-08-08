// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Interfaces
import { I1271Policy } from "@smartsessions/interfaces/IPolicy.sol";
import { IERC165 } from "@forge-std/interfaces/IERC165.sol";

// Libraries
import { ConfigLib, PolicyConfig } from "@policies/claim-recipient/lib/ConfigLib.sol";
import { StorageLib, PolicyStorage } from "@policies/claim-recipient/lib/StorageLib.sol";
import { DecodeLib } from "@policies/claim-recipient/lib/DecodeLib.sol";
import { ArgPolicyTreeLibV2 } from "@policies/claim-recipient/lib/ArgPolicyTreeLibV2.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import {
    ParamRules,
    TokenInConfig,
    TokenOutConfig
} from "@policies/claim-recipient/types/DataTypes.sol";

// Temp
// solhint-disable no-console
import { console } from "@forge-std/console.sol";

/// @title MultiChainClaimPolicy
/// @notice A policy that allows enforcing rules on specific fields of a MultiChainClaim struct:
///         - hasExecutions: executions != empty executions hash
///         - recipient + targetChainId: compare with input
///         - tokenIn/amount: per chainId mapping
///         - tokenOut/amount: per targetChainId mapping
///         - qualification: compare with input
///         Uses a bitmap configuration with separate storage for each condition
contract MultiChainClaimPolicy is I1271Policy {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using ConfigLib for PolicyConfig;
    using ConfigLib for bytes;
    using DecodeLib for bytes;
    using ArgPolicyTreeLibV2 for ParamRules;

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    /*//////////////////////////////////////////////////////////////
                                  INIT
    //////////////////////////////////////////////////////////////*/

    /// @notice Initializes the policy with a comprehensive configuration
    /// @param account The account to initialize
    /// @param configId The configuration ID for the policy
    /// @param initData The initialization data containing the PolicyConfig
    function initializeWithMultiplexer(
        address account,
        ConfigId configId,
        bytes calldata initData
    )
        external
        override
    {
        // Parse policy config from first byte of initData
        PolicyConfig config = PolicyConfig.wrap(uint8(initData[0]));

        // Set the policy configuration for the account if the bitmap is not empty
        if (config != PolicyConfig.wrap(0)) {
            // Use the remaining bytes of initData for further configuration
            initData = initData[1:];
            // We only need to load the fields at the offset that are set in the bitmap
            setConfig(account, configId, config, initData);
        } else {
            // Get policy storage pointer
            PolicyStorage storage $ = StorageLib.getPolicyStorage();
            // Store the sudo configuration
            $.policyConfig[configId][msg.sender][account] = config;
        }
    }

    /*//////////////////////////////////////////////////////////////
                                 CONFIG
    //////////////////////////////////////////////////////////////*/

    /// @notice Sets the configurations for the enabled conditions, this function only parses the
    ///         configuration data that is set in the bitmap.
    /// @param account The account to set the configuration for
    /// @param configId The configuration ID for the policy
    /// @param configBitmap Bitmap representing enabled conditions
    /// @param configData Additional configuration data for the conditions
    function setConfig(
        address account,
        ConfigId configId,
        PolicyConfig configBitmap,
        bytes calldata configData
    )
        internal
    {
        // Process configuration data based on the bitmap

        // (0) hasExecutions

        // if (configBitmap.hasCheckHasExecutions()) {
        ///    This condition doesn't need any additional data
        // }

        // Get policy storage pointer
        PolicyStorage storage $ = StorageLib.getPolicyStorage();

        // (1) qualification
        if (configBitmap.hasCheckQualification()) {
            // Decode qualification configuration
            ParamRules memory qualificationConfig;
            bytes32 qualificationTypehash;
            (qualificationConfig, configData, qualificationTypehash) =
                configData.decodeQualificationConfig();
            console.log("Qualification typehash:");
            console.logBytes32(qualificationTypehash);
            // Store the qualification configuration
            $.qualificationConfig[configId][msg.sender][account][qualificationTypehash].fill(
                qualificationConfig
            );
        }

        // (2) recipient and targetChainId
        if (configBitmap.hasCheckRecipientAndTargetChain()) {
            // Decode recipient and target chain configuration
            uint256 targetChainId;
            address recipient;
            (targetChainId, recipient, configData) = configData.decodeRecipientAndTargetChain();
            // Store recipient and target chain configuration
            $.recipientConfig[configId][msg.sender][account][targetChainId] = recipient;
        }

        // (3) tokenIn
        if (configBitmap.hasCheckTokenIn()) {
            // Decode tokenIn configuration
            TokenInConfig[] memory tokenInConfigs;
            (tokenInConfigs, configData) = configData.decodeTokenInConfig();
            // Store the tokenIn configurations
            for (uint256 i = 0; i < tokenInConfigs.length; i++) {
                TokenInConfig memory tokenInConfig = tokenInConfigs[i];
                $.tokenInConfig[configId][msg.sender][account][tokenInConfig.chainId] =
                    tokenInConfig.config;
            }
        }

        // (4) tokenOut
        if (configBitmap.hasCheckTokenOut()) {
            // Decode tokenOut configuration
            TokenOutConfig[] memory tokenOutConfigs;
            (tokenOutConfigs, configData) = configData.decodeTokenOutConfig();
            // Store the tokenOut configurations
            for (uint256 i = 0; i < tokenOutConfigs.length; i++) {
                TokenOutConfig memory tokenOutConfig = tokenOutConfigs[i];
                $.tokenOutConfig[configId][msg.sender][account][tokenOutConfig.targetChainId] =
                    tokenOutConfig.config;
            }
        }

        // Store the bitmap configuration
        $.policyConfig[configId][msg.sender][account] = configBitmap;
    }

    /*//////////////////////////////////////////////////////////////
                                 CHECK
    //////////////////////////////////////////////////////////////*/

    /// @notice Checks if the action is allowed based on the MultiChainClaim struct and the policy
    ///         configuration, the function uses the raw data from the signature to reconstruct
    ///         the MultiChainClaim struct and recalculate its hash. If either the struct params
    ///         or the hash match don't match the policy configuration, the action is not allowed.
    /// @param id The configuration ID for the policy
    /// @param account The account to check the action for
    /// @param hash The hash of the action to check
    /// @param signature The signature of the action to check, containing the actual signature and
    /// additional data used to reconstruct the MultiChainClaim struct
    /// @dev The signature is expected to be in the format:
    ///      [actual_sig_length][actual_signature][raw_multichain_claim_data]
    function check1271SignedAction(
        ConfigId id,
        address, /*sender*/
        address account,
        bytes32 hash,
        bytes calldata signature
    )
        external
        view
        override
        returns (bool)
    {
        // Get policy storage pointer
        PolicyStorage storage $ = StorageLib.getPolicyStorage();

        // Load the policy configuration bitmap
        PolicyConfig config = $.policyConfig[id][msg.sender][account];

        console.log("Checking MultiChainClaimPolicy for account:", account);
        console.log("Conditions bitmap:", PolicyConfig.unwrap(config));

        // If no conditions are enabled, allow everything (sudo mode)
        if (config == PolicyConfig.wrap(0)) {
            console.log("No conditions enabled - allowing all actions");
            return true;
        }

        // Extract the hash and validate the parameters from the signature
        // using the raw data and the stored configuration for the account
        (bool isValid, bytes32 recomputedHash) = signature.extractAndValidate(config, id, account);

        console.log("Recomputed hash:");
        console.logBytes32(recomputedHash);
        console.log("Original hash:");
        console.logBytes32(hash);
        console.log("Is valid:", isValid);

        // If the recomputed hash does not match the provided hash, return false
        return isValid && recomputedHash == hash;
    }

    /*//////////////////////////////////////////////////////////////
                                  VIEW
    //////////////////////////////////////////////////////////////*/

    /// @notice Checks if the policy supports the given interface ID
    function supportsInterface(bytes4 interfaceID) external pure override returns (bool) {
        return (
            interfaceID == type(IERC165).interfaceId || interfaceID == type(I1271Policy).interfaceId
        );
    }
}
