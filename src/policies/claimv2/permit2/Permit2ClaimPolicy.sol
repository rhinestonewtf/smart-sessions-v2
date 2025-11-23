// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Interfaces
import { I1271Policy } from "@smartsessions/interfaces/IPolicy.sol";
import { IERC165 } from "@forge-std/interfaces/IERC165.sol";

// Libraries
import { Permit2ConfigLib, PolicyConfig } from "@policies/claimv2/permit2/lib/ConfigLib.sol";
import { Permit2StorageLib, PolicyStorage } from "@policies/claimv2/permit2/lib/StorageLib.sol";
import { Permit2DecodeLib } from "@policies/claimv2/permit2/lib/DecodeLib.sol";
import { EnumerableSetLib } from "solady/utils/EnumerableSetLib.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import {
    SubPolicyConfig,
    ParamRules,
    TokenInStorageConfig,
    RecipientStorageConfig,
    FillExpiryStorageConfig,
    TokenOutStorageConfig,
    OriginOpsStorageConfig,
    DestOpsStorageConfig,
    QualificationStorageConfig,
    MODE_SKIP,
    MODE_CHECK_STORAGE,
    MODE_CHECK_CATCHALL,
    MODE_CHECK_SUBPOLICY,
    FIELD_ARBITER,
    FIELD_DEADLINE,
    FIELD_TOKEN_IN,
    FIELD_RECIPIENT,
    FIELD_FILL_EXPIRY,
    FIELD_TOKEN_OUT,
    FIELD_ORIGIN_OPS,
    FIELD_DEST_OPS,
    FIELD_QUALIFICATION
} from "@policies/claimv2/permit2/types/DataTypes.sol";

/// @title Permit2ClaimPolicy
/// @notice Policy for validating Permit2 batch transfers with Mandate witness data
/// @dev Validates Permit2 signatures with Mandate witness according to configured rules
contract Permit2ClaimPolicy is I1271Policy {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using Permit2ConfigLib for uint8;
    using Permit2ConfigLib for uint32;
    using Permit2ConfigLib for bytes;
    using Permit2ConfigLib for PolicyConfig;
    using Permit2DecodeLib for bytes;
    using EnumerableSetLib for EnumerableSetLib.AddressSet;

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown when an invalid mode is provided for a field
    error InvalidMode();
    /// @notice Thrown when the initialization data is invalid
    error InvalidInitData();
    /// @notice Thrown when an invalid chainId is provided based on the mode
    error InvalidChainId();

    /*//////////////////////////////////////////////////////////////
                                  INIT
    //////////////////////////////////////////////////////////////*/

    /// @notice Initializes the policy configuration for a specific account and session
    /// @dev This function is called by the SmartSession multiplexer during policy installation
    /// @param account The account for which the policy is being configured
    /// @param configId The unique identifier for this policy configuration
    /// @param initData Encoded policy configuration data:
    ///                 - First 4 bytes: modeConfig (2 bits per field)
    ///                 - Remaining bytes: field-specific configuration data
    function initializeWithMultiplexer(
        address account,
        ConfigId configId,
        bytes calldata initData
    )
        external
        override
    {
        // Decode mode config from first 4 bytes
        uint32 modeConfig = uint32(bytes4(initData[0:4]));

        // Get storage
        PolicyStorage storage $ = Permit2StorageLib.getPolicyStorage();

        // Revert if modeConfig is zero (no conditions enabled)
        if (modeConfig == 0) {
            revert InvalidInitData();
        }

        // Store the mode configuration
        $.modeConfig[configId][msg.sender][account] = modeConfig;

        // Use the remaining bytes for field configuration
        bytes calldata configData = initData[4:];

        // Set the configuration based on enabled modes
        _setConfig(account, configId, modeConfig, configData);
    }

    /*//////////////////////////////////////////////////////////////
                                 CONFIG
    //////////////////////////////////////////////////////////////*/

    /// @notice Internal function to set field configurations based on mode configuration
    /// @dev Decodes and stores configuration for each enabled field
    /// @param account The account to configure
    /// @param configId The configuration ID
    /// @param modeConfig The mode configuration bitmap
    /// @param configData Field-specific configuration data
    function _setConfig(
        address account,
        ConfigId configId,
        uint32 modeConfig,
        bytes calldata configData
    )
        internal
    {
        // Get policy storage pointer
        PolicyStorage storage $ = Permit2StorageLib.getPolicyStorage();

        // Decode the initialization data
        Permit2ConfigLib.InitData memory init =
            Permit2ConfigLib.decodeInitData(modeConfig, configData);

        // Initialize storage-based configs
        _initializeArbiter($, configId, account, init);
        _initializeDeadline($, configId, account, init);
        _initializeTokenIn($, configId, account, init);
        _initializeRecipient($, configId, account, init);
        _initializeFillExpiry($, configId, account, init);
        _initializeTokenOut($, configId, account, init);
        _initializeOriginOps($, configId, account, init);
        _initializeDestOps($, configId, account, init);
        _initializeQualification($, configId, account, init);

        // Initialize sub-policies
        _initializeSubPolicies($, configId, account, init.subPolicies, modeConfig);
    }

    /*//////////////////////////////////////////////////////////////
                            INITIALIZATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Initializes arbiter configuration
    function _initializeArbiter(
        PolicyStorage storage $,
        ConfigId configId,
        address account,
        Permit2ConfigLib.InitData memory init
    )
        private
    {
        uint8 mode = init.modeConfig.getFieldMode(FIELD_ARBITER);

        if (mode == MODE_CHECK_STORAGE) {
            $.arbiterConfig[configId][msg.sender][account] = init.arbiter;
        }
    }

    /// @notice Initializes deadline configuration
    function _initializeDeadline(
        PolicyStorage storage $,
        ConfigId configId,
        address account,
        Permit2ConfigLib.InitData memory init
    )
        private
    {
        uint8 mode = init.modeConfig.getFieldMode(FIELD_DEADLINE);

        if (mode == MODE_CHECK_STORAGE) {
            uint256 packed = Permit2ConfigLib.packUint128(init.minDeadline, init.maxDeadline);
            $.deadlineConfig[configId][msg.sender][account] = packed;
        }
    }

    /// @notice Initializes tokenIn configuration
    function _initializeTokenIn(
        PolicyStorage storage $,
        ConfigId configId,
        address account,
        Permit2ConfigLib.InitData memory init
    )
        private
    {
        uint8 mode = init.modeConfig.getFieldMode(FIELD_TOKEN_IN);

        if (mode.isStorageMode()) {
            for (uint256 i = 0; i < init.tokenInConfigs.length; i++) {
                TokenInStorageConfig memory config = init.tokenInConfigs[i];

                // Validate chainId based on mode
                _validateChainIdForMode(config.chainId, mode);

                // Add token to set
                $.tokenInSet[configId][msg.sender][account][config.chainId].add(config.token);
            }
        }
    }

    /// @notice Initializes recipient configuration
    function _initializeRecipient(
        PolicyStorage storage $,
        ConfigId configId,
        address account,
        Permit2ConfigLib.InitData memory init
    )
        private
    {
        uint8 mode = init.modeConfig.getFieldMode(FIELD_RECIPIENT);

        if (mode.isStorageMode()) {
            for (uint256 i = 0; i < init.recipientConfigs.length; i++) {
                RecipientStorageConfig memory config = init.recipientConfigs[i];

                _validateChainIdForMode(config.targetChainId, mode);

                $.recipientConfig[configId][msg.sender][account][config.targetChainId] =
                config.recipient;
            }
        }
    }

    /// @notice Initializes fillExpiry configuration
    function _initializeFillExpiry(
        PolicyStorage storage $,
        ConfigId configId,
        address account,
        Permit2ConfigLib.InitData memory init
    )
        private
    {
        uint8 mode = init.modeConfig.getFieldMode(FIELD_FILL_EXPIRY);

        if (mode.isStorageMode()) {
            for (uint256 i = 0; i < init.fillExpiryConfigs.length; i++) {
                FillExpiryStorageConfig memory config = init.fillExpiryConfigs[i];

                _validateChainIdForMode(config.targetChainId, mode);

                uint256 packed =
                    Permit2ConfigLib.packUint128(config.minFillExpiry, config.maxFillExpiry);
                $.fillExpiryConfig[configId][msg.sender][account][config.targetChainId] = packed;
            }
        }
    }

    /// @notice Initializes tokenOut configuration
    function _initializeTokenOut(
        PolicyStorage storage $,
        ConfigId configId,
        address account,
        Permit2ConfigLib.InitData memory init
    )
        private
    {
        uint8 mode = init.modeConfig.getFieldMode(FIELD_TOKEN_OUT);

        if (mode.isStorageMode()) {
            for (uint256 i = 0; i < init.tokenOutConfigs.length; i++) {
                TokenOutStorageConfig memory config = init.tokenOutConfigs[i];

                _validateChainIdForMode(config.targetChainId, mode);

                $.tokenOutSet[configId][msg.sender][account][config.targetChainId].add(config.token);
            }
        }
    }

    /// @notice Initializes originOps configuration
    function _initializeOriginOps(
        PolicyStorage storage $,
        ConfigId configId,
        address account,
        Permit2ConfigLib.InitData memory init
    )
        private
    {
        uint8 mode = init.modeConfig.getFieldMode(FIELD_ORIGIN_OPS);

        if (mode.isStorageMode()) {
            for (uint256 i = 0; i < init.originOpsConfigs.length; i++) {
                OriginOpsStorageConfig memory config = init.originOpsConfigs[i];

                _validateChainIdForMode(config.chainId, mode);

                $.originOpsConfig[configId][msg.sender][account][config.chainId] =
                config.requireOriginOps;
            }
        }
    }

    /// @notice Initializes destOps configuration
    function _initializeDestOps(
        PolicyStorage storage $,
        ConfigId configId,
        address account,
        Permit2ConfigLib.InitData memory init
    )
        private
    {
        uint8 mode = init.modeConfig.getFieldMode(FIELD_DEST_OPS);

        if (mode.isStorageMode()) {
            for (uint256 i = 0; i < init.destOpsConfigs.length; i++) {
                DestOpsStorageConfig memory config = init.destOpsConfigs[i];

                _validateChainIdForMode(config.targetChainId, mode);

                $.destOpsConfig[configId][msg.sender][account][config.targetChainId] =
                config.requireDestOps;
            }
        }
    }

    /// @notice Initializes qualification configuration
    function _initializeQualification(
        PolicyStorage storage $,
        ConfigId configId,
        address account,
        Permit2ConfigLib.InitData memory init
    )
        private
    {
        uint8 mode = init.modeConfig.getFieldMode(FIELD_QUALIFICATION);

        if (mode.isStorageMode()) {
            for (uint256 i = 0; i < init.qualificationConfigs.length; i++) {
                QualificationStorageConfig memory config = init.qualificationConfigs[i];

                _validateChainIdForMode(config.chainId, mode);

                ParamRules storage rules = $.qualificationConfig[
                    configId
                ][msg.sender][account][config.chainId][config.arbiter];

                // Store the rules
                rules.rootNodeIndex = config.rules.rootNodeIndex;

                // Store param rules
                for (uint256 j = 0; j < config.rules.rules.length; j++) {
                    rules.rules.push(config.rules.rules[j]);
                }

                // Store packed nodes
                for (uint256 j = 0; j < config.rules.packedNodes.length; j++) {
                    rules.packedNodes.push(config.rules.packedNodes[j]);
                }
            }
        }
    }

    /// @notice Validates chainId based on mode
    /// @dev MODE_CHECK_STORAGE requires chainId > 0, MODE_CHECK_CATCHALL allows chainId == 0
    function _validateChainIdForMode(uint256 chainId, uint8 mode) private pure {
        if (mode == MODE_CHECK_STORAGE && chainId == 0) {
            revert InvalidChainId();
        }
    }

    /// @notice Initializes sub-policy configurations
    /// @dev For each sub-policy, stores the policy address and initializes it
    function _initializeSubPolicies(
        PolicyStorage storage $,
        ConfigId configId,
        address account,
        SubPolicyConfig[] memory subPolicies,
        uint32 modeConfig
    )
        private
    {
        for (uint256 i = 0; i < subPolicies.length; i++) {
            SubPolicyConfig memory subPolicy = subPolicies[i];

            // Verify the field is set to MODE_CHECK_SUBPOLICY
            uint8 mode = modeConfig.getFieldMode(subPolicy.fieldId);
            if (mode != MODE_CHECK_SUBPOLICY) {
                revert InvalidMode();
            }

            // Store the sub-policy address
            $.subPolicies[configId][msg.sender][account][subPolicy.fieldId] =
            subPolicy.policyAddress;

            // Initialize the sub-policy
            I1271Policy(subPolicy.policyAddress)
                .initializeWithMultiplexer(account, configId, subPolicy.initData);
        }
    }

    /*//////////////////////////////////////////////////////////////
                                 CHECK
    //////////////////////////////////////////////////////////////*/

    /// @notice Validates a Permit2 signature with Mandate witness against configured rules
    /// @dev This is the main validation entry point called by the SmartSession system
    /// @param id The configuration ID for this policy
    /// @param account The account whose action is being validated
    /// @param hash The hash of the action being validated
    /// @param signature The signature data containing Permit2 and Mandate information
    /// @return True if the signature is valid according to the policy, false otherwise
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
        PolicyStorage storage $ = Permit2StorageLib.getPolicyStorage();

        // Load the mode configuration
        uint32 modeConfigRaw = $.modeConfig[id][msg.sender][account];

        // If no conditions are enabled, return false
        if (modeConfigRaw == 0) {
            return false;
        }

        PolicyConfig config = PolicyConfig.wrap(modeConfigRaw);

        // Extract and validate Permit2 + Mandate data
        (bool isValid, bytes32 recomputedHash) =
            signature.extractAndValidate(config, id, account, hash);

        // Verify the recomputed hash matches the provided hash
        return isValid && recomputedHash == hash;
    }

    /*//////////////////////////////////////////////////////////////
                                  VIEW
    //////////////////////////////////////////////////////////////*/

    /// @notice Checks if this contract implements the given interface
    /// @param interfaceID The interface identifier to check
    /// @return True if the interface is supported
    function supportsInterface(bytes4 interfaceID) external pure override returns (bool) {
        return
            (interfaceID == type(IERC165).interfaceId
                    || interfaceID == type(I1271Policy).interfaceId);
    }
}
