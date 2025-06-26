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

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import {
    ActionConfig,
    ParamRules,
    ParamRule
} from "@smartsessions/external/policies/ArgPolicy/ArgPolicy.sol"; // TODO: remove Limit from
    // paramrules

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
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    /*//////////////////////////////////////////////////////////////
                                ENUMS
    //////////////////////////////////////////////////////////////*/

    enum ConditionFlagsBytes {
        CHECK_HAS_EXECUTIONS, // 0
        CHECK_PRE_CLAIM_OPS, // 1
        CHECK_RECIPIENT_AND_TARGET_CHAIN, // 2
        CHECK_TOKEN_IN, // 3
        CHECK_TOKEN_OUT // 4

    }

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    type PolicyConfig is uint8; // Bitmap to determine which conditions to check

    /*//////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Token amount configuration for checking per chain
    struct TokenAmountConfig {
        address token; // Token address (address(0) for any token)
        uint128 minAmount; // Minimum amount (0 for no minimum)
        uint128 maxAmount; // Maximum amount (type(uint128).max for no maximum)
    }

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
    mapping(ConfigId id => mapping(address msgSender => ActionConfig preClaimOpsConfig)) internal
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
        // Parse the policy configuration from initData

        // Validate configuration

        // Store the configuration
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
        bytes32 recomputedHash = _rehashMultichainCompact(multichainCompact);
        if (recomputedHash != hash) {
            console.log("Hash mismatch!");
            return false;
        }

        // Check each condition based on the bitmap
        return _checkAllConditions(config, multichainCompact);
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
}
