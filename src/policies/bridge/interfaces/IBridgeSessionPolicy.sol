// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

// Interfaces
import { I1271Policy } from "@smartsessions/interfaces/IPolicy.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";

/// @title IBridgeSessionPolicy
/// @author Rhinestone
/// @notice Interface for BridgeSessionPolicy - one session, several settlement layers, one spend
interface IBridgeSessionPolicy is I1271Policy {
    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown when init data is too short to hold a nonce and a layer count
    /// @param length The length supplied
    error InvalidInitDataLength(uint256 length);

    /// @notice Thrown when init data names a layer this policy does not know
    /// @param layer The layer identifier supplied
    error UnknownLayer(uint8 layer);

    /// @notice Thrown when init data names the same layer twice
    /// @param layer The layer identifier supplied
    error DuplicateLayer(uint8 layer);

    /// @notice Thrown when a layer is configured without a settlement policy
    error MissingLayerPolicy();

    /// @notice Thrown when a settlement policy does not implement I1271Policy
    /// @param policy The address supplied
    error InvalidLayerPolicy(address policy);

    /// @notice Thrown when one settlement policy is named for more than one layer
    /// @dev The layer tag is unsigned; a mis-tagged payload is only stopped because it reaches a
    ///      different policy that rejects it on its own digest binding
    /// @param policy The address supplied twice
    error DuplicateLayerPolicy(address policy);

    /*//////////////////////////////////////////////////////////////
                                 VIEWS
    //////////////////////////////////////////////////////////////*/

    /// @notice Returns the nonce pinned for a configuration
    /// @param configId The configuration ID
    /// @param multiplexer The multiplexer that initialized the configuration
    /// @param account The account the configuration belongs to
    /// @return configured Whether the session has been set up
    /// @return nonce The pinned nonce, meaningless when `configured` is false
    function getPinnedNonce(
        ConfigId configId,
        address multiplexer,
        address account
    )
        external
        view
        returns (bool configured, uint256 nonce);

    /// @notice Returns the settlement policy permitted for a layer
    /// @param configId The configuration ID
    /// @param multiplexer The multiplexer that initialized the configuration
    /// @param account The account the configuration belongs to
    /// @param layer The settlement layer
    /// @return policy The settlement policy, or zero if this layer is not permitted
    function getLayerPolicy(
        ConfigId configId,
        address multiplexer,
        address account,
        uint8 layer
    )
        external
        view
        returns (address policy);
}
