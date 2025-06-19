// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Interfaces
import { IStatelessValidator } from "@compact-utils/interfaces/IStatelessValidator.sol";

// Types
import { Session } from "@smartsessions/DataTypes.sol";
import { ResetPeriod, Scope } from "@compact-utils/interfaces/IEmissary.sol";
import { EnableSession, PermissionId } from "@smartsessions/DataTypes.sol";

/*//////////////////////////////////////////////////////////////
                            CONSTANTS
//////////////////////////////////////////////////////////////*/

/// @dev Invalid return value for unsupported or invalid operations
bytes4 constant INVALID_RETURN = 0xFFFFFFFF;

/*//////////////////////////////////////////////////////////////
                            STRUCTS
//////////////////////////////////////////////////////////////*/

/// @notice Configuration for the Smart Session Emissary.
/// @dev This configuration is used to set up the Smart Session Emissary with multiple sessions,
///      a scope, a reset period, and an allocator address.
struct SmartSessionEmissaryConfig {
    address arbiter;
    address sender;
    Scope scope;
    ResetPeriod resetPeriod;
    address allocator;
    EnableSession session;
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
/// @dev This structure contains the signatures, expiration time, nonce, and chain IDs
///      for enabling an Emissary on a specific chain.
struct EmissaryEnable {
    bytes allocatorSig;
    bytes userSig;
    uint256 expires;
    uint256 nonce;
    uint256[] allChainIds;
    uint256 chainIndex;
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
