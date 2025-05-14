// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Types
import { PermissionId, SmartSessionMode } from "@smartsessions/DataTypes.sol";

interface ISmartSessionEmissary {
    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown when the sender is not a whitelisted source
    error UnauthorizedSource();

    /// @notice Thrown when the calldata selector is not supported
    error UnsupportedSelector();

    /// @notice Thrown when the data is not valid
    error InvalidData();

    /// @notice Thrown when the session is not valid
    error InvalidSession(PermissionId permissionId);

    /// @notice Thrown when a permission ID is not valid
    error InvalidPermissionId(PermissionId permissionId);

    /// @notice Thrown when the session mode is not supported
    error UnsupportedSmartSessionMode(SmartSessionMode mode);

    /// @notice Thrown when the execution type is not supported
    error UnsupportedExecutionType();

    /// @notice Thrown when the enable session signature is not valid
    error InvalidEnableSignature(address account, bytes32 hash);

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when a session is created
    event SessionCreated(PermissionId permissionId, address account);

    /// @notice Emitted when a session is removed
    event SessionRemoved(PermissionId permissionId, address smartAccount);

    /*//////////////////////////////////////////////////////////////
                                 VERIFY
    //////////////////////////////////////////////////////////////*/

    function verifyExecution(
        address account,
        bytes32 hash,
        bytes calldata emissaryData,
        bytes calldata executions
    )
        external
        returns (bytes4);
}
