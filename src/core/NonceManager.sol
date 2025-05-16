// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

// Types
import { PermissionId } from "@smartsessions/DataTypes.sol";

/// @title NonceManager
/// @dev Abstract contract for managing nonces for smart sessions
abstract contract NonceManager {
    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when the nonce is incremented
    event NonceIterated(PermissionId permissionId, address indexed account, uint256 nonce);

    /*//////////////////////////////////////////////////////////////
                                 STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @dev Mapping to store nonces for each permission ID and smart account
    mapping(PermissionId permissionId => mapping(address smartAccount => uint256 nonce)) internal
        $signerNonce;

    /*//////////////////////////////////////////////////////////////
                                GETTERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get the current nonce for a given permission ID and account
    /// @param permissionId The permission ID
    /// @param account The smart account address
    /// @return The current nonce value
    function getNonce(PermissionId permissionId, address account) external view returns (uint256) {
        return $signerNonce[permissionId][account];
    }

    /*//////////////////////////////////////////////////////////////
                                SETTERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Revoke the current enable signature by incrementing the nonce
    /// @param permissionId The permission ID to revoke the signature for
    function revokeEnableSignature(PermissionId permissionId) external {
        // Increment the nonce and store the old value
        uint256 nonce = $signerNonce[permissionId][msg.sender]++;
        emit NonceIterated(permissionId, msg.sender, nonce + 1);
    }
}
