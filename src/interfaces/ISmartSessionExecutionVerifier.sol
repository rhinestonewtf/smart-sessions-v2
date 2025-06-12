// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Types
import { PermissionId, SmartSessionMode } from "@smartsessions/DataTypes.sol";

interface ISmartSessionExecutionVerifier {
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

    /// @notice Emitted when an address whitelist status is updated
    event WhitelistStatusUpdated(address source, bool status);

    /*//////////////////////////////////////////////////////////////
                                 VERIFY
    //////////////////////////////////////////////////////////////*/

    /// @notice Validates executions for an account using it's enabled policies
    /// @dev This function is called by a whitelisted source, which is assumed to verify that
    ///      executions are included in the hash that is passed to this function and signed by the
    ///      session key
    /// @param account The account for which the policies are being enforced
    /// @param hash The hash of the user operation
    /// @param data Packed smart session data including mode, permissionId and signature
    /// @param executions The execution data for the user operation
    /// @return bytes4 The function selector on success, or a specific failure code otherwise
    function verifyExecution(
        address account,
        bytes32 hash,
        bytes calldata data,
        bytes calldata executions
    )
        external
        returns (bytes4);
}
