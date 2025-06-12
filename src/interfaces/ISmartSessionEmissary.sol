// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Interfaces
import { IEmissary } from "@compact-utils/interfaces/IEmissary.sol";
import { IStatelessValidator } from "@compact-utils/interfaces/IStatelessValidator.sol";

// Types
import { SmartSessionEmissaryConfig, EmissaryConfig, EmissaryEnable } from "@types/DataTypes.sol";
import { PermissionId, SmartSessionMode } from "@smartsessions/DataTypes.sol";

interface ISmartSessionEmissary is IEmissary {
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

    /// @notice Thrown when the Emissary enable data is not valid
    error InvalidEmissaryEnableData();

    /// @notice Thrown when the Emissary configuration is not valid
    error InvalidEmissaryConfig();

    /// @notice Thrown when the Emissary enable data allocator signature is not valid
    error InvalidAllocatorSignature();

    /// @notice Thrown when the Emissary enable data user signature is not valid
    error InvalidUserSignature();

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when a session is created
    event SessionCreated(PermissionId permissionId, address account);

    /// @notice Emitted when a session is removed
    event SessionRemoved(PermissionId permissionId, address smartAccount);

    /// @notice Emitted when an address whitelist status is updated
    event WhitelistStatusUpdated(address source, bool status);

    /// @notice Emitted when a new validator configuration is successfully set for an account and
    ///         lock tag.
    /// @param account The sponsor account whose configuration was updated.
    /// @param validator The stateless validator address associated with the configuration.
    /// @param lockTag The lock tag derived from the allocator, scope, and reset period.
    event EmissaryConfigUpdated(
        address indexed account, IStatelessValidator indexed validator, bytes12 indexed lockTag
    );

    /*//////////////////////////////////////////////////////////////
                                 CONFIG
    //////////////////////////////////////////////////////////////*/

    /// @notice Sets the Smart Session Emissary configuration for a specific account.
    /// @param account The address of the account for which the configuration is being set.
    /// @param config The Smart Session Emissary configuration.
    /// @param enable The Emissary enable data.
    function setConfig(
        address account,
        SmartSessionEmissaryConfig calldata config,
        EmissaryEnable calldata enable
    )
        external;

    /// @notice Sets the vanilla Emissary configuration for a specific account.
    /// @param account The address of the account for which the configuration is being set.
    /// @param config The Emissary configuration.
    /// @param enable The Emissary enable data.
    function setConfig(
        address account,
        EmissaryConfig calldata config,
        EmissaryEnable calldata enable
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
        bytes calldata executions
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
