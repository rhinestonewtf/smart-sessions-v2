// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Interfaces
import { IEmissary } from "@compact-utils/interfaces/IEmissary.sol";

// Types
import {
    SmartSessionEmissaryConfig,
    SmartSessionEmissaryEnable,
    SmartSessionEmissaryDisable
} from "@types/DataTypes.sol";
import { PermissionId } from "@smartsessions/DataTypes.sol";
import { Types } from "@rhinestone/compact-utils/src/types/OrderTypes.sol";

interface ISmartSessionEmissary is IEmissary {
    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown when the msg.sender is not the intent executor
    error UnauthorizedSource();

    /// @notice Thrown when the session is not valid
    error InvalidSession(PermissionId permissionId);

    /// @notice Thrown when a permission ID is not valid
    error InvalidPermissionId(PermissionId permissionId);

    /// @notice Thrown when the Emissary enable data is not valid
    error InvalidEmissaryEnableData();

    /// @notice Thrown when the Emissary enable data allocator signature is not valid
    error InvalidAllocatorSignature();

    /// @notice Thrown when the Emissary enable data user signature is not valid
    error InvalidUserSignature();

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when a Smart Session Emissary configuration is successfully set for an
    ///         account.
    /// @param account The address of the account for which the configuration was set.
    /// @param permissionId The permission ID associated with the Smart Session.
    /// @param lockTag The lock tag derived from the allocator, scope, and reset period.
    event SmartSessionEmissaryConfigEnabled(
        address indexed account, PermissionId permissionId, bytes12 indexed lockTag
    );

    /*//////////////////////////////////////////////////////////////
                                 CONFIG
    //////////////////////////////////////////////////////////////*/

    /// @notice Sets the Smart Session Emissary configuration for a specific account.
    /// @param account The address of the account for which the configuration is being set.
    /// @param config The Smart Session Emissary configuration.
    /// @param enable The Smart Session Emissary enable data.
    function setConfig(
        address account,
        SmartSessionEmissaryConfig calldata config,
        SmartSessionEmissaryEnable calldata enable
    )
        external;

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
        Types.Operation calldata executions
    )
        external
        returns (bytes4);

    /// @notice Verifies claims with mode-based dispatch to appropriate verification method
    /// @param sponsor The sponsor account associated with the claim
    /// @param digest The hash of the claim being verified (for traditional modes)
    /// @param claimHash The claim hash being verified (for SmartSession mode)
    /// @param emissaryData Data containing mode byte and mode-specific verification data
    /// @param lockTag The lock tag associated with the claim
    /// @return The selector if valid, otherwise 0xFFFFFFFF
    function verifyClaim(
        address sponsor,
        bytes32 digest,
        bytes32 claimHash,
        bytes calldata emissaryData,
        bytes12 lockTag
    )
        external
        view
        returns (bytes4);
}
