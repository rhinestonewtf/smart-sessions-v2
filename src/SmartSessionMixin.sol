// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Contracts
import { SmartSessionManager } from "@core/SmartSessionManager.sol";

// Interfaces

// Libraries

// Types
import {
    PermissionId, SmartSessionMode, EnableSession, Session
} from "@smartsessions/DataTypes.sol";
import { SmartSessionEmissaryConfig, EmissaryEnable } from "@interfaces/ISmartSessionEmissary.sol";

/// @title SmartSessionMixin
/// @notice Mixin providing SmartSession functionality for emissaries
/// @dev Bridges lockTag-based emissary system with permissionId-based SmartSession system
abstract contract SmartSessionMixin is SmartSessionManager {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Maps lockTag to enabled permissionIds for verifyClaim lookups
    /// @dev Bridge storage connecting emissary lockTags to SmartSession permissionIds
    mapping(
        address sponsor
            => mapping(bytes12 lockTag => mapping(PermissionId permissionId => bool enabled))
    ) public smartSessionConfig;

    /*//////////////////////////////////////////////////////////////
                                CONFIG
    //////////////////////////////////////////////////////////////*/

    /// @notice Sets the Smart Session Emissary configuration for a specific account
    /// @param account The address of the account for which the configuration is being set
    /// @param config The Smart Session Emissary configuration
    /// @param enableData The Emissary enable data
    function setConfig(
        address account,
        SmartSessionEmissaryConfig calldata config,
        EmissaryEnable calldata enableData
    )
        external
        virtual
    {
        // Derive lockTag from allocator, scope, resetPeriod
        // bytes12 lockTag = config.allocator.usingAllocatorId().toLockTag(config.scope,
        // config.resetPeriod);

        // Nonce validation to prevent replay attacks
        // - Get current nonce for account + lockTag from $emissaryNonce
        // - Require enableData.nonce > currentNonce
        // - Update stored nonce

        // Security validations
        // - Verify chain ID matches current chain
        // - Verify enableData.expires > block.timestamp
        // - Calculate EIP-712 hash for session configuration
        // - Verify user signature (if msg.sender != account)
        // - Verify allocator signature

        // Remove existing sessions for this lockTag
        // - Iterate through existing smartSessionConfig[account][lockTag]
        // - Call removeSession() for each enabled permissionId
        // - Clear mapping entries

        // Enable new sessions if provided
        // if (config.sessions.length > 0) {
        //     // Call _enableSessions(config.sessions, false) to enable in SmartSession
        // infrastructure
        //     // Map returned permissionIds to lockTag in smartSessionConfig
        //     // Set smartSessionConfig[account][lockTag][permissionId] = true for each
        // }

        //  Emit session configuration update event
    }

    /*//////////////////////////////////////////////////////////////
                            CLAIM VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Verifies claims using SmartSession (mode 2)
    /// @param sponsor The sponsor account associated with the claim
    /// @param claimHash The hash of the claim being verified
    /// @param emissaryData Data containing the permissionId and ERC-7739 signature
    /// @param lockTag The lock tag associated with the claim
    /// @return The selector if valid, otherwise 0xFFFFFFFF
    function _verifyClaimSmartSession(
        address sponsor,
        bytes32 claimHash,
        bytes calldata emissaryData,
        bytes12 lockTag
    )
        internal
        view
        virtual
        returns (bytes4)
    {
        // Parse emissaryData format for SmartSession:
        // [permissionId: 32 bytes][ERC-7739 data: remaining]

        // Extract permissionId from first 32 bytes
        // PermissionId permissionId = PermissionId.wrap(bytes32(emissaryData[:32]));

        // Validate permissionId is enabled for this lockTag
        // require(smartSessionConfig[sponsor][lockTag][permissionId], "Session not enabled for
        // lockTag");

        // Verify session is still enabled in SmartSession infrastructure
        // require(isPermissionEnabled(permissionId, sponsor), "Session not enabled");

        // Extract ERC-7739 signature data
        // bytes calldata erc7739Data = emissaryData[32:];

        // Perform ERC-7739 signature validation
        // - Use _erc1271IsValidSignatureViaNestedEIP712()
        // - Pass sponsor, claimHash, and unwrapped signature
        // - Return appropriate selector or failure

        return bytes4(0xFFFFFFFF); // Placeholder
    }

    /*//////////////////////////////////////////////////////////////
                         EXECUTION VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Validates executions using SmartSession policies
    /// @param account The account for which the policies are being enforced
    /// @param hash The hash of the user operation
    /// @param emissaryData Packed smart session data including mode, permissionId and signature
    /// @param executions The execution data for the user operation
    /// @return bytes4 The function selector on success, or a specific failure code otherwise
    function _verifyExecutionSmartSession(
        address account,
        bytes32 hash,
        bytes calldata emissaryData,
        bytes calldata executions
    )
        external
        virtual
        returns (bytes4)
    {
        // Validate mode is for SmartSession execution
        // uint8 mode = uint8(emissaryData[0]);
        // require(mode == 2, "Invalid mode for SmartSession execution");

        // Unpack SmartSession data from emissaryData[1:]
        // (SmartSessionMode ssMode, PermissionId permissionId, bytes calldata packedSig) =
        // emissaryData[1:].unpackMode();

        // Handle USE mode
        // if (ssMode.isUseMode()) {
        //     // Call _enforcePolicies with permissionId, hash, executions, signature, account
        //     // Return success selector or failure
        // }
        // Enable mode not supported?
        //  Revert for unsupported modes
    }
}
