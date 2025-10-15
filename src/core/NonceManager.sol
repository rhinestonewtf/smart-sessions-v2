// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

/// @title Nonce Manager
/// @dev Abstract contract for managing nonces for smart sessions and emissary configs
abstract contract NonceManager {
    /* //////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when the nonce is incremented
    event NonceIterated(bytes12 lockTag, address indexed account, uint256 nonce);

    /* //////////////////////////////////////////////////////////////
                                 STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @dev Mapping to store nonces for each sponsor and lockTag
    mapping(address sponsor => mapping(bytes12 lockTag => uint256 nonce)) internal $emissaryNonce;

    /* //////////////////////////////////////////////////////////////
                                GETTERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get the current nonce for a given lock tag and sponsor
    /// @param sponsor The sponsor address
    /// @param lockTag The lock tag associated with the nonce
    function getNonce(address sponsor, bytes12 lockTag) external view returns (uint256) {
        return $emissaryNonce[sponsor][lockTag];
    }

    /* //////////////////////////////////////////////////////////////
                                SETTERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Revoke the current nonce for a given lock tag, sponsor being the caller
    /// @param lockTag The lock tag associated with the nonce to be revoked
    function revokeNonce(bytes12 lockTag) external {
        uint256 nonce = ++$emissaryNonce[msg.sender][lockTag];
        emit NonceIterated(lockTag, msg.sender, nonce);
    }
}
