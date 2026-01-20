// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import {
    PolicyConfig,
    QualificationRulesStorage
} from "@policies/claim/base/types/BaseDataTypes.sol";

/// @title IBaseClaimPolicy
/// @author Rhinestone
/// @notice Interface for BaseClaimPolicy view functions
/// @dev Provides read access to policy configuration state
interface IBaseClaimPolicy {
    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown when policy initialization fails due to invalid configuration data
    error InvalidConfigurationData();

    /// @notice Thrown when attempting to initialize a policy that already exists for an account and
    ///         config ID
    error ConfigurationAlreadyExists();

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when a policy is initialized for an account
    /// @param configId The configuration ID
    /// @param account The account that was initialized
    /// @param modeConfig The mode configuration bitmap
    event PolicyInitialized(
        ConfigId indexed configId, address indexed account, PolicyConfig modeConfig
    );

    /*//////////////////////////////////////////////////////////////
                              MODE CONFIG
    //////////////////////////////////////////////////////////////*/

    /// @notice Returns the mode configuration for an account
    /// @param configId The configuration ID
    /// @param account The account to query
    /// @return The mode configuration bitmap
    function getModeConfig(ConfigId configId, address account) external view returns (PolicyConfig);

    /*//////////////////////////////////////////////////////////////
                                ARBITER
    //////////////////////////////////////////////////////////////*/

    /// @notice Returns the whitelisted arbiters for an account
    /// @param configId The configuration ID
    /// @param account The account to query
    /// @return arbiters Array of whitelisted arbiter addresses
    function getArbiters(
        ConfigId configId,
        address account
    )
        external
        view
        returns (address[] memory arbiters);

    /// @notice Checks if an arbiter is whitelisted
    /// @param configId The configuration ID
    /// @param account The account to query
    /// @param arbiter The arbiter address to check
    /// @return True if the arbiter is whitelisted
    function isArbiterWhitelisted(
        ConfigId configId,
        address account,
        address arbiter
    )
        external
        view
        returns (bool);

    /*//////////////////////////////////////////////////////////////
                                 EXPIRY
    //////////////////////////////////////////////////////////////*/

    /// @notice Returns the claim expiry bounds for an account
    /// @param configId The configuration ID
    /// @param account The account to query
    /// @return minExpiry The minimum expiry timestamp
    /// @return maxExpiry The maximum expiry timestamp
    function getExpiryBounds(
        ConfigId configId,
        address account
    )
        external
        view
        returns (uint128 minExpiry, uint128 maxExpiry);

    /*//////////////////////////////////////////////////////////////
                               RECIPIENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Returns the configured recipient for a chain
    /// @param configId The configuration ID
    /// @param account The account to query
    /// @param chainId The target chain ID
    /// @return The recipient address
    function getRecipient(
        ConfigId configId,
        address account,
        uint256 chainId
    )
        external
        view
        returns (address);

    /*//////////////////////////////////////////////////////////////
                              FILL EXPIRY
    //////////////////////////////////////////////////////////////*/

    /// @notice Returns the fill expiry bounds for a chain
    /// @param configId The configuration ID
    /// @param account The account to query
    /// @param chainId The target chain ID
    /// @return minFillExpiry The minimum fill expiry timestamp
    /// @return maxFillExpiry The maximum fill expiry timestamp
    function getFillExpiryBounds(
        ConfigId configId,
        address account,
        uint256 chainId
    )
        external
        view
        returns (uint128 minFillExpiry, uint128 maxFillExpiry);

    /*//////////////////////////////////////////////////////////////
                               TOKEN OUT
    //////////////////////////////////////////////////////////////*/

    /// @notice Returns the whitelisted output tokens for a chain
    /// @param configId The configuration ID
    /// @param account The account to query
    /// @param chainId The target chain ID
    /// @return tokens Array of whitelisted token addresses
    function getTokensOut(
        ConfigId configId,
        address account,
        uint256 chainId
    )
        external
        view
        returns (address[] memory tokens);

    /// @notice Checks if a token is whitelisted for output on a chain
    /// @param configId The configuration ID
    /// @param account The account to query
    /// @param chainId The target chain ID
    /// @param token The token address to check
    /// @return True if the token is whitelisted
    function isTokenOutWhitelisted(
        ConfigId configId,
        address account,
        uint256 chainId,
        address token
    )
        external
        view
        returns (bool);

    /*//////////////////////////////////////////////////////////////
                                    OPS
    //////////////////////////////////////////////////////////////*/

    /// @notice Returns whether origin operations are required for a chain
    /// @param configId The configuration ID
    /// @param account The account to query
    /// @param chainId The origin chain ID
    /// @return True if origin operations are required
    function getOriginOpsRequired(
        ConfigId configId,
        address account,
        uint256 chainId
    )
        external
        view
        returns (bool);

    /// @notice Returns whether destination operations are required for a chain
    /// @param configId The configuration ID
    /// @param account The account to query
    /// @param chainId The destination chain ID
    /// @return True if destination operations are required
    function getDestOpsRequired(
        ConfigId configId,
        address account,
        uint256 chainId
    )
        external
        view
        returns (bool);

    /*//////////////////////////////////////////////////////////////
                            QUALIFICATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Returns the qualification rules for a chain/arbiter pair
    /// @param configId The configuration ID
    /// @param account The account to query
    /// @param chainId The chain ID
    /// @param arbiter The arbiter address
    /// @return rules Qualification rules storage struct
    function getQualificationRules(
        ConfigId configId,
        address account,
        uint256 chainId,
        address arbiter
    )
        external
        view
        returns (QualificationRulesStorage memory rules);

    /*//////////////////////////////////////////////////////////////
                              SUB-POLICY
    //////////////////////////////////////////////////////////////*/

    /// @notice Returns the sub-policy address for a field
    /// @param configId The configuration ID
    /// @param account The account to query
    /// @param fieldId The field ID (0-9, see FIELD_* constants)
    /// @return The sub-policy contract address
    function getSubPolicy(
        ConfigId configId,
        address account,
        uint8 fieldId
    )
        external
        view
        returns (address);
}
