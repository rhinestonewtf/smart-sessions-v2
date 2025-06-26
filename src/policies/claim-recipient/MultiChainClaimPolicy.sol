// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Interfaces
import { I1271Policy } from "@smartsessions/interfaces/IPolicy.sol";
import { IERC165 } from "@forge-std/interfaces/IERC165.sol";

// Contracts
import { EIP712TypeHash } from "@compact-utils/types/EIP712TypeHash.sol";

// Libraries
import { ArgPolicyTreeLib } from
    "@smartsessions/external/policies/ArgPolicy/lib/ArgPolicyTreeLib.sol";
import { ConfigLib, PolicyConfig } from "@policies/claim-recipient/lib/ConfigLib.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import {
    TokenInConfig,
    TokenOutConfig,
    ParamRules,
    ParamRule,
    TokenAmountConfig
} from "@policies/claim-recipient/types/DataTypes.sol";

/// @title MultiChainClaimPolicy
/// @notice A policy that allows enforcing rules on specific fields of a MultiChainClaim struct:
///         - hasExecutions: executions != empty executions hash
///         - preClaimOps: compare with input (allow specific addresses, data, etc)
///         - recipient + targetChainId: compare with input
///         - tokenIn/amount: per chainId mapping
///         - tokenOut/amount: per targetChainId mapping
///         Uses a bitmap configuration with separate storage for each condition
contract MultiChainClaimPolicy is I1271Policy, EIP712TypeHash {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using ConfigLib for PolicyConfig;
    using ConfigLib for bytes;

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Mapping to store the policy configuration for each account and config ID
    mapping(
        ConfigId id
            => mapping(
                address msgSender => mapping(address userOpSender => PolicyConfig conditionsBitmap)
            )
    ) internal $policyConfig;

    /// @notice Mapping to store token amount configurations per chain id
    mapping(
        ConfigId id
            => mapping(
                address msgSender => mapping(uint256 chainId => TokenAmountConfig tokenInConfig)
            )
    ) internal $tokenInConfig;

    /// @notice Mapping to store token amount configurations per target chain id
    mapping(
        ConfigId id
            => mapping(
                address msgSender
                    => mapping(uint256 targetChainId => TokenAmountConfig tokenOutConfig)
            )
    ) internal $tokenOutConfig;

    /// @notice Mapping to recipient configurations per chain target chain id
    mapping(
        ConfigId id
            => mapping(address msgSender => mapping(uint256 targetChainId => address recipient))
    ) internal $recipientConfig;

    /// @notice Mapping to store pre-claim operations configurations
    mapping(ConfigId id => mapping(address msgSender => ParamRules preClaimOpsConfig)) internal
        $preClaimOpsConfig;

    /*//////////////////////////////////////////////////////////////
                                CONSTANTS
    //////////////////////////////////////////////////////////////*/

    bytes32 private constant EMPTY_EXECUTIONS_HASH =
        0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470;

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
            setConfig(configId, config, initData);
        } else {
            // Store the sudo configuration
            $policyConfig[configId][msg.sender][account] = config;
        }
    }

    /*//////////////////////////////////////////////////////////////
                                 CONFIG
    //////////////////////////////////////////////////////////////*/

    /// @notice Sets the configurations for the enabled conditions, this function only parses the
    ///         configuration data that is set in the bitmap.
    /// @param configId The configuration ID for the policy
    /// @param configBitmap Bitmap representing enabled conditions
    /// @param configData Additional configuration data for the conditions
    function setConfig(
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

        // (1) preClaimOps
        if (configBitmap.hasCheckPreClaimOps()) {
            // Decode preClaimOps configuration
            ParamRules memory preClaimOpsConfig;
            (preClaimOpsConfig, configData) = configData.decodePreClaimOpsConfig();
            // Store the preClaimOps configuration
            $preClaimOpsConfig[configId][msg.sender] = preClaimOpsConfig;
        }

        // (2) recipient and targetChainId
        if (configBitmap.hasCheckRecipientAndTargetChain()) {
            // Decode recipient and target chain configuration
            uint256 targetChainId;
            address recipient;
            (targetChainId, recipient, configData) = configData.decodeRecipientAndTargetChain();
            // Store recipient and target chain configuration
            $recipientConfig[configId][msg.sender][targetChainId] = recipient;
        }

        // (3) tokenIn
        if (configBitmap.hasCheckTokenIn()) {
            // Decode tokenIn configuration
            TokenInConfig[] memory tokenInConfigs;
            (tokenInConfigs, configData) = configData.decodeTokenInConfig();
            // Store the tokenIn configurations
            for (uint256 i = 0; i < tokenInConfigs.length; i++) {
                TokenInConfig memory tokenInConfig = tokenInConfigs[i];
                $tokenInConfig[configId][msg.sender][tokenInConfig.chainId] = tokenInConfig.config;
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
                $tokenOutConfig[configId][msg.sender][tokenOutConfig.targetChainId] =
                    tokenOutConfig.config;
            }
        }

        // Store the bitmap configuration
        $policyConfig[configId][msg.sender][msg.sender] = configBitmap;
    }

    /*//////////////////////////////////////////////////////////////
                                 CHECK
    //////////////////////////////////////////////////////////////*/

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
        // Load the policy configuration
        // Extract and decode the MultichainCompact from signature
        // Verify hash integrity
        // bytes32 recomputedHash = _rehashMultichainCompact(multichainCompact);
        // if (recomputedHash != hash) {
        //     console.log("Hash mismatch!");
        //     return false;
        // }
        // Check each condition based on the bitmap
        // return _checkAllConditions(config, multichainCompact);
    }

    /*//////////////////////////////////////////////////////////////
                                INTERNAL
    //////////////////////////////////////////////////////////////*/

    /*//////////////////////////////////////////////////////////////
                                  VIEW
    //////////////////////////////////////////////////////////////*/

    /// @notice Checks if the policy supports the given interface ID
    function supportsInterface(bytes4 interfaceID) external pure override returns (bool) {
        return (
            interfaceID == type(IERC165).interfaceId || interfaceID == type(I1271Policy).interfaceId
        );
    }

    function __QUALIFIER_EIP712Hash(bytes calldata data)
        public
        view
        virtual
        override
        returns (bytes32)
    { }
}
