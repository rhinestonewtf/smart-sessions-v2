// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

// Interfaces
import { I1271Policy, IActionPolicy } from "@smartsessions/interfaces/IPolicy.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";

/// @title INoncePinPolicy
/// @author Rhinestone
/// @notice Interface for NoncePinPolicy - pins one nonce for a session and refuses wherever it
/// has already been spent
/// @dev Serves both settlement surfaces: the Permit2 claim path as a 1271 policy, the intent
/// executor path as an action policy
interface INoncePinPolicy is I1271Policy, IActionPolicy {
    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown when init data is not exactly one 32-byte nonce
    /// @param length The length supplied
    error InvalidInitDataLength(uint256 length);

    /*//////////////////////////////////////////////////////////////
                                 VIEWS
    //////////////////////////////////////////////////////////////*/

    /// @notice Returns the pinned nonce for a configuration
    /// @param configId The configuration ID
    /// @param multiplexer The multiplexer that initialized the configuration
    /// @param account The account the configuration belongs to
    /// @return configured Whether a nonce has been pinned
    /// @return nonce The pinned nonce, meaningless when `configured` is false
    function getPinnedNonce(
        ConfigId configId,
        address multiplexer,
        address account
    )
        external
        view
        returns (bool configured, uint256 nonce);
}
