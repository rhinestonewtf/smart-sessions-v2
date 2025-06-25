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
    PolicyData
} from "@smartsessions/DataTypes.sol";

/*//////////////////////////////////////////////////////////////
                            CONSTANTS
//////////////////////////////////////////////////////////////*/

/// @dev Invalid return value for unsupported or invalid operations
bytes4 constant INVALID_RETURN = 0xFFFFFFFF;

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
///     erc1271Policies (PolicyData[]): An array of policy data for specifying ERC-1271 policies.
///
///     actions (ActionData[]): An array of action data for specifying function-specific policies.
///         A common use case of session keys is to scope access to a specific target and function
///         selector. SmartSession calls this "Action". With ActionData, we can specify policies
///         that are only run if a 7579 execution contains a specific action.
struct Session {
    ISessionValidator sessionValidator;
    bytes sessionValidatorInitData;
    bytes32 salt;
    PolicyData[] erc1271Policies;
    ActionData[] actions;
}

/// @notice Configuration for the Smart Session Emissary.
/// @dev This configuration is used to set up the Smart Session Emissary with multiple sessions,
///      a scope, a reset period, and an allocator address.
struct SmartSessionEmissaryConfig {
    address arbiter;
    address sender;
    Scope scope;
    ResetPeriod resetPeriod;
    address allocator;
    PermissionId permissionId;
}

/// @notice Configuration for the basic Emissary.
/// @dev This configuration is used to set up the Emissary with a specific allocator,
///      a scope, a reset period, and a stateless validator.
struct EmissaryConfig {
    uint8 configId;
    address allocator;
    Scope scope;
    ResetPeriod resetPeriod;
    IStatelessValidator validator;
    bytes validatorConfig;
}

/// @notice Data structure for enabling an Emissary.
/// @dev This structure contains the signatures, expiration time, chain IDs
///      for enabling an Emissary on a specific chain.
struct EmissaryEnable {
    bytes allocatorSig;
    bytes userSig;
    uint256 expires;
    uint256[] allChainIds;
    uint256 chainIndex;
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

/// @notice Structure holding WebAuthn credential information
/// @dev Maps a credential ID to its public key and verification requirements
/// @param pubKeyX The X coordinate of the credential's public key on the P-256 curve
/// @param pubKeyY The Y coordinate of the credential's public key on the P-256 curve
/// @param requireUV Whether user verification (biometrics/PIN) is required for this credential
struct WebAuthnCredential {
    uint256 pubKeyX;
    uint256 pubKeyY;
    bool requireUV;
}

/// @notice WebAuthVerificationContext
/// @dev Context for WebAuthn verification, including credential details and threshold
/// @param usePrecompile Whether to use the RIP7212 precompile for signature verification,
///                      or fallback to FreshCryptoLib. According to ERC-7562, calling the
///                      precompile is only allowed on networks that support it.
/// @param threshold The number of signatures required for validation
/// @param credentialIds The IDs of the credentials used for signing
/// @param credential data WebAuthn credential data
struct WebAuthVerificationContext {
    bool usePrecompile;
    uint256 threshold;
    bytes32[] credentialIds;
    WebAuthnCredential[] credentialData;
}
