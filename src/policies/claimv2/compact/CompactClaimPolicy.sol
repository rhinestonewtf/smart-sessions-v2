// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Interfaces
import { I1271Policy } from "@smartsessions/interfaces/IPolicy.sol";
import { IERC165 } from "@forge-std/interfaces/IERC165.sol";

// Libraries
import { ConfigLib, PolicyConfig } from "@policies/claimv2/compact/lib/ConfigLib.sol";
import { StorageLib, PolicyStorage } from "@policies/claimv2/compact/lib/StorageLib.sol";
import { DecodeLib } from "@policies/claimv2/compact/lib/DecodeLib.sol";
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
    FIELD_CLAIM_EXPIRES,
    FIELD_TOKEN_IN,
    FIELD_RECIPIENT,
    FIELD_FILL_EXPIRY,
    FIELD_TOKEN_OUT,
    FIELD_ORIGIN_OPS,
    FIELD_DEST_OPS,
    FIELD_QUALIFICATION
} from "@policies/claimv2/compact/types/DataTypes.sol";

/// @title CompactClaimPolicy
/// @notice A policy that allows enforcing rules on specific fields of a Compact Claim struct:
///     MultiChainCompact:
///     - arbiter: address
///     - expires: uint256
///     >>> Lock[] TokenIn
///         - token: address
///         - lockTag: bytes12
///     >>> Mandate
///         >>> Target
///             - recipient: address
///             - targetChain: uint256
///             - fillExpiry: uint256
///             >>> Token[] TokenOut
///                 - token: address
///         >>> Op originOps: bool
///         >>> Op destOps: bool
///         >>> Qualification: bytes
contract CompactClaimPolicy is I1271Policy {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using ConfigLib for uint8;
    using ConfigLib for uint32;
    using ConfigLib for bytes;
    using ConfigLib for PolicyConfig;
    using DecodeLib for bytes;
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;
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

    /// @notice Initializes the policy with the provided configuration
    /// @param account The account to initialize
    /// @param configId The configuration ID for the policy
    /// @param initData The initialization data containing the mode configuration and field configs
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
        PolicyStorage storage $ = StorageLib.getPolicyStorage();

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

    /// @notice Sets the configurations for the enabled fields based on the mode configuration
    /// @param account The account to set the configuration for
    /// @param configId The configuration ID for the policy
    /// @param modeConfig Mode configuration (2 bits per field)
    /// @param configData Additional configuration data for the fields
    function _setConfig(
        address account,
        ConfigId configId,
        uint32 modeConfig,
        bytes calldata configData
    )
        internal
    {
        // Get policy storage pointer
        PolicyStorage storage $ = StorageLib.getPolicyStorage();

        // TODO: Remove unnecessary memory copy here and work with calldata directly
        // Decode the initialization data
        ConfigLib.InitData memory init = ConfigLib.decodeInitData(modeConfig, configData);

        // Initialize storage-based configs
        _initializeArbiter($, configId, account, init);
        _initializeClaimExpires($, configId, account, init);
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
        ConfigLib.InitData memory init
    )
        private
    {
        // Extract mode for arbiter field
        uint8 mode = init.modeConfig.getFieldMode(FIELD_ARBITER);

        // Only store arbiter if mode is MODE_CHECK_STORAGE
        if (mode == MODE_CHECK_STORAGE) {
            $.arbiterConfig[configId][msg.sender][account] = init.arbiter;
        }
    }

    /// @notice Initializes claim expires configuration
    function _initializeClaimExpires(
        PolicyStorage storage $,
        ConfigId configId,
        address account,
        ConfigLib.InitData memory init
    )
        private
    {
        // Extract mode for claim expires field
        uint8 mode = init.modeConfig.getFieldMode(FIELD_CLAIM_EXPIRES);

        // Only store claim expires if mode is MODE_CHECK_STORAGE
        if (mode == MODE_CHECK_STORAGE) {
            uint256 packed = ConfigLib.packUint128(init.minClaimExpires, init.maxClaimExpires);
            $.claimExpiresConfig[configId][msg.sender][account] = packed;
        }
    }

    /// @notice Initializes tokenIn configuration
    function _initializeTokenIn(
        PolicyStorage storage $,
        ConfigId configId,
        address account,
        ConfigLib.InitData memory init
    )
        private
    {
        // Extract mode for tokenIn field
        uint8 mode = init.modeConfig.getFieldMode(FIELD_TOKEN_IN);

        // Only if mode is storage-based
        if (mode.isStorageMode()) {
            for (uint256 i = 0; i < init.tokenInConfigs.length; i++) {
                TokenInStorageConfig memory config = init.tokenInConfigs[i];

                // Validate chainId based on mode
                _validateChainIdForMode(config.chainId, mode);

                bytes32 packed = ConfigLib.packTokenIn(config.token, config.lockTag);
                $.tokenInSet[configId][msg.sender][account][config.chainId].add(packed);
            }
        }
    }

    /// @notice Initializes recipient configuration
    function _initializeRecipient(
        PolicyStorage storage $,
        ConfigId configId,
        address account,
        ConfigLib.InitData memory init
    )
        private
    {
        // Extract mode for recipient field
        uint8 mode = init.modeConfig.getFieldMode(FIELD_RECIPIENT);

        // Only if mode is storage-based
        if (mode.isStorageMode()) {
            for (uint256 i = 0; i < init.recipientConfigs.length; i++) {
                RecipientStorageConfig memory config = init.recipientConfigs[i];

                // Validate targetChainId based on mode
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
        ConfigLib.InitData memory init
    )
        private
    {
        // Extract mode for fillExpiry field
        uint8 mode = init.modeConfig.getFieldMode(FIELD_FILL_EXPIRY);

        // Only if mode is storage-based
        if (mode.isStorageMode()) {
            for (uint256 i = 0; i < init.fillExpiryConfigs.length; i++) {
                FillExpiryStorageConfig memory config = init.fillExpiryConfigs[i];

                // Validate targetChainId based on mode
                _validateChainIdForMode(config.targetChainId, mode);

                uint256 packed = ConfigLib.packUint128(config.minFillExpiry, config.maxFillExpiry);
                $.fillExpiryConfig[configId][msg.sender][account][config.targetChainId] = packed;
            }
        }
    }

    /// @notice Initializes tokenOut configuration
    function _initializeTokenOut(
        PolicyStorage storage $,
        ConfigId configId,
        address account,
        ConfigLib.InitData memory init
    )
        private
    {
        // Extract mode for tokenOut field
        uint8 mode = init.modeConfig.getFieldMode(FIELD_TOKEN_OUT);

        // Only if mode is storage-based
        if (mode.isStorageMode()) {
            for (uint256 i = 0; i < init.tokenOutConfigs.length; i++) {
                TokenOutStorageConfig memory config = init.tokenOutConfigs[i];

                // Validate targetChainId based on mode
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
        ConfigLib.InitData memory init
    )
        private
    {
        // Extract mode for originOps field
        uint8 mode = init.modeConfig.getFieldMode(FIELD_ORIGIN_OPS);

        // Only if mode is storage-based
        if (mode.isStorageMode()) {
            for (uint256 i = 0; i < init.originOpsConfigs.length; i++) {
                OriginOpsStorageConfig memory config = init.originOpsConfigs[i];

                // Validate chainId based on mode
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
        ConfigLib.InitData memory init
    )
        private
    {
        // Extract mode for destOps field
        uint8 mode = init.modeConfig.getFieldMode(FIELD_DEST_OPS);

        // Only if mode is storage-based
        if (mode.isStorageMode()) {
            for (uint256 i = 0; i < init.destOpsConfigs.length; i++) {
                DestOpsStorageConfig memory config = init.destOpsConfigs[i];

                // Validate targetChainId based on mode
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
        ConfigLib.InitData memory init
    )
        private
    {
        // Extract mode for qualification field
        uint8 mode = init.modeConfig.getFieldMode(FIELD_QUALIFICATION);

        // Only if mode is storage-based
        if (mode.isStorageMode()) {
            for (uint256 i = 0; i < init.qualificationConfigs.length; i++) {
                QualificationStorageConfig memory config = init.qualificationConfigs[i];

                // Validate chainId based on mode
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
    /// @dev If mode is MODE_CHECK_STORAGE, chainId must be > 0
    /// @dev If mode is MODE_CHECK_CATCHALL, chainId can be 0 (catch-all) or > 0 (specific)
    function _validateChainIdForMode(uint256 chainId, uint8 mode) private pure {
        if (mode == MODE_CHECK_STORAGE && chainId == 0) {
            revert InvalidChainId();
        }
    }

    /// @notice Initializes sub-policy configurations
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

            // Verify the field is actually set to MODE_CHECK_SUBPOLICY
            uint8 mode = modeConfig.getFieldMode(subPolicy.fieldId);
            if (mode != MODE_CHECK_SUBPOLICY) {
                revert InvalidMode();
            }

            // Store the sub-policy address
            $.subPolicies[configId][msg.sender][account][subPolicy.fieldId] =
            subPolicy.policyAddress;

            // Initialize the sub-policy with the provided initData
            I1271Policy(subPolicy.policyAddress)
                .initializeWithMultiplexer(account, configId, subPolicy.initData);
        }
    }

    /*//////////////////////////////////////////////////////////////
                                 CHECK
    //////////////////////////////////////////////////////////////*/

    /// @notice Checks if the signature is valid based on the Compact claim and the policy
    ///         configuration. The function uses the raw data from the signature to reconstruct
    ///         the Compact struct and recalculate its hash. If either the struct params
    ///         or the hash don't match the policy configuration, the action is not allowed.
    /// @param id The configuration ID for the policy
    /// @param account The account to check the signature for
    /// @param hash The hash of the action to check
    /// @param signature Data used to reconstruct the Compact struct
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

        // Load the mode configuration
        uint32 modeConfigRaw = $.modeConfig[id][msg.sender][account];

        // If no conditions are enabled, always return false
        if (modeConfigRaw == 0) {
            return false;
        }

        PolicyConfig config = PolicyConfig.wrap(modeConfigRaw);

        // Extract the hash and validate the parameters from the signature
        // using the raw data and the stored configuration for the account
        (bool isValid, bytes32 recomputedHash) =
            signature.extractAndValidate(config, id, account, hash);

        // If the recomputed hash does not match the provided hash, return false
        return isValid && recomputedHash == hash;
    }

    /*//////////////////////////////////////////////////////////////
                                  VIEW
    //////////////////////////////////////////////////////////////*/

    /// @notice Checks if the policy supports the given interface ID
    function supportsInterface(bytes4 interfaceID) external pure override returns (bool) {
        return
            (interfaceID == type(IERC165).interfaceId
                    || interfaceID == type(I1271Policy).interfaceId);
    }
}
