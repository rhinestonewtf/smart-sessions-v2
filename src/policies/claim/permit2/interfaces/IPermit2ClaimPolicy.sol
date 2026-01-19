// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { IBaseClaimPolicy } from "@policies/claim/base/interfaces/IBaseClaimPolicy.sol";
import { ConfigId } from "@smartsessions/DataTypes.sol";

/// @title IPermit2ClaimPolicy
/// @author Rhinestone
/// @notice Interface for Permit2ClaimPolicy - validates Permit2 PermitBatchWitnessTransferFrom
/// signatures @dev Extends IBaseClaimPolicy with Permit2-specific tokenIn handling (token only, no
/// lockTag)
interface IPermit2ClaimPolicy is IBaseClaimPolicy {
    /*//////////////////////////////////////////////////////////////
                                 VIEWS
    //////////////////////////////////////////////////////////////*/

    /// @notice Returns the whitelisted tokenIn entries for a chain
    /// @param configId The configuration ID
    /// @param account The account to query
    /// @param chainId The chain ID
    /// @return tokens Array of whitelisted token addresses
    function getTokenInWhitelist(
        ConfigId configId,
        address account,
        uint256 chainId
    )
        external
        view
        returns (address[] memory tokens);

    /// @notice Checks if a token is whitelisted
    /// @param configId The configuration ID
    /// @param account The account to query
    /// @param chainId The chain ID
    /// @param token The token address
    /// @return True if the token is whitelisted
    function isTokenInWhitelisted(
        ConfigId configId,
        address account,
        uint256 chainId,
        address token
    )
        external
        view
        returns (bool);
}
