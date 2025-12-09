// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Interfaces
import { IStatelessValidator } from "@compact-utils/interfaces/IStatelessValidator.sol";
import { ISessionValidator } from "@smartsessions/interfaces/ISessionValidator.sol";

// Types
import { ResetPeriod, Scope } from "@compact-utils/interfaces/IEmissary.sol";
import {
    PermissionId,
    ChainDigest,
    ActionData,
    PolicyData,
    ERC7739Data
} from "@smartsessions/DataTypes.sol";

/*//////////////////////////////////////////////////////////////
                            CONSTANTS
//////////////////////////////////////////////////////////////*/

/// @dev Invalid return value for unsupported or invalid operations
bytes4 constant INVALID_SIGNATURE = 0xFFFFFFFF;

/// @dev Sentinel lockTag value used for sessions without a lockTag
bytes12 constant NO_LOCKTAG = bytes12(0);

/*//////////////////////////////////////////////////////////////
                            STRUCTS
//////////////////////////////////////////////////////////////*/

/// @notice Data structure for enabling a session.
/// @dev This structure contains the chain digest index, hashes and chain IDs,
///      and the session to enable.
struct EnableSession {
    uint8 chainDigestIndex;
    ChainDigest[] hashesAndChainIds;
    Session sessionToEnable;
}

/// @notice Data structure for disabling a session.
/// @dev This structure contains the chain digest index, hashes and chain IDs
struct DisableSession {
    uint8 chainDigestIndex;
    ChainDigest[] hashesAndChainIds;
}

/// Represents a Session structure with various attributes for managing user operations and
/// policies.
///
/// Attributes:
///     sessionValidator (ISessionValidator): The validator contract for signing user operations.
///         Every userOp must be signed by the session key "owner". The signature is validated
///         via a stateless external contract (ISessionValidator) that can implement different
///         means of validation.
///
///     sessionValidatorInitData (bytes): Initialization data for the ISessionValidator contract.
///         The ISessionValidator contract can be configured with different parameters that are
///         passed in this field.
///
///     salt (bytes32): A unique identifier to prevent collision between sessions.
///         A session key owner can have multiple sessions with the same parameters. To facilitate
///         this, a salt is necessary to avoid collision.
///
///     actions (ActionData[]): An array of action data for specifying function-specific policies.
///         A common use case of session keys is to scope access to a specific target and function
///         selector. SmartSession calls this "Action". With ActionData, we can specify policies
///         that are only run if a 7579 execution contains a specific action.
///
///     claimPolicies (PolicyData[]): ERC-1271 policies for Compact claim verification.
///         These policies are enforced during verifyClaim calls and are stored per lockTag,
///         allowing different signing permissions for different Compact allocator contexts.
///
///     erc7739Policies (ERC7739Data): ERC-1271 policies specific to the ERC-7739 standard.
///         These policies are used for general message signing via isValidSignature and are
///         stored globally (not lockTag-specific), enabling broad signing capabilities.
struct Session {
    ISessionValidator sessionValidator;
    bytes sessionValidatorInitData;
    bytes32 salt;
    ActionData[] actions;
    PolicyData[] claimPolicies;
    ERC7739Data erc7739Policies;
}

/// @notice Configuration for the Smart Session Emissary.
/// @dev This configuration is used to set up the Smart Session Emissary with multiple sessions,
///      a scope, a reset period, and an allocator address.
struct SmartSessionEmissaryConfig {
    Scope scope;
    ResetPeriod resetPeriod;
    address allocator;
    PermissionId permissionId;
}

/// @notice Data structure for enabling a Smart Session Emissary.
/// @dev This structure contains the signatures, and EnableSession data
struct SmartSessionEmissaryEnable {
    bytes allocatorSig;
    bytes userSig;
    uint256 expires;
    EnableSession session;
}

/// @notice Data structure for disabling a Smart Session Emissary configuration.
/// @dev This structure contains the signatures, and DisableSession data
struct SmartSessionEmissaryDisable {
    bytes allocatorSig;
    bytes userSig;
    uint256 expires;
    DisableSession session;
}

