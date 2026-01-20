// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

import { IBaseClaimPolicy } from "@policies/claim/base/interfaces/IBaseClaimPolicy.sol";
import { ConfigId } from "@smartsessions/DataTypes.sol";

/// @title ICompactClaimPolicy
/// @author Rhinestone
/// @notice Interface for CompactClaimPolicy - validates Compact protocol MultichainCompact
/// signatures @dev Extends IBaseClaimPolicy with Compact-specific tokenIn handling (token +
/// lockTag)
interface ICompactClaimPolicy is IBaseClaimPolicy {
    /*//////////////////////////////////////////////////////////////
                                 VIEWS
    //////////////////////////////////////////////////////////////*/

    /// @notice Returns the whitelisted tokenIn entries for a chain
    /// @param configId The configuration ID
    /// @param account The account to query
    /// @param chainId The chain ID
    /// @return tokens Array of packed bytes32 values (token + lockTag)
    function getTokenInWhitelist(
        ConfigId configId,
        address account,
        uint256 chainId
    )
        external
        view
        returns (bytes32[] memory tokens);

    /// @notice Checks if a token + lockTag combination is whitelisted
    /// @param configId The configuration ID
    /// @param account The account to query
    /// @param chainId The chain ID
    /// @param token The token address
    /// @param lockTag The lock tag
    /// @return True if the combination is whitelisted
    function isTokenInWhitelisted(
        ConfigId configId,
        address account,
        uint256 chainId,
        address token,
        bytes12 lockTag
    )
        external
        view
        returns (bool);
}
