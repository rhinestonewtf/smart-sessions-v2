// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

// Libraries
import { EfficientHashLib } from "@solady/utils/EfficientHashLib.sol";
import { HashLib } from "@smartsessions/lib/HashLib.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

// Types
import {
    FALLBACK_TARGET_FLAG,
    FALLBACK_TARGET_SELECTOR_FLAG,
    FALLBACK_TARGET_SELECTOR_FLAG_PERMITTED_TO_CALL_SMARTSESSION,
    ChainDigest,
    ActionData,
    PolicyData,
    PermissionId,
    ERC7739Data
} from "@smartsessions/DataTypes.sol";
import { EnableSession, DisableSession, Session } from "@types/DataTypes.sol";

/*//////////////////////////////////////////////////////////////
                            TYPEHASHES
//////////////////////////////////////////////////////////////*/

/// @dev LockTagData(bytes12 lockTag, PolicyData[] claimPolicies)
///
///      Encapsulates claim policies scoped to a specific lockTag.
///      The lockTag is derived from allocator + scope + resetPeriod.
bytes32 constant LOCKTAG_DATA_TYPEHASH =
    0x530e6ac3fbb108eb531208da75d7310b7086a7d16b42cbb119ebd7543f7a1955;

/// @dev SignedPermissions(
///          ActionData[] actions,
///          ERC7739Data erc7739Policies,
///          LockTagData lockTagPolicies,
///          bool permitGenericPolicy
///      )
bytes32 constant SIGNED_PERMISSIONS_TYPEHASH =
    0xa6d649a3e6014c0f8cf1e42d360388616413c96247ed3e994eeff9e3ac2af36f;

/// @dev SignedSession(
///          address account,                              // User account address
///          uint256 expires,                              // Expiration timestamp
///          uint256 nonce,                                // Nonce value
///          SignedPermissions permissions,                // Signed permissions struct
///          │   ActionData[] actions                      // Actions array
///          │   ├── bytes4 actionTargetSelector           // Function selector
///          │   ├── address actionTarget                  // Target contract
///          │   └── PolicyData[] actionPolicies           // Action policies array
///          │       ├── address policy                    // Policy address
///          │       └── bytes initData                    // Init data
///          │   ERC7739Data erc7739Policies               // ERC7739 policies struct
///          │   ├── ERC7739Context[] allowedERC7739Content// Allowed content array
///          │   │   ├── bytes32 appDomainSeparator        // Domain separator
///          │   │   └── string[] contentName              // Content identifiers
///          │   └── PolicyData[] erc1271Policies          // ERC1271 policies array
///          │       ├── address policy                    // Policy address
///          │       └── bytes initData                    // Init data
///          │   LockTagData lockTagPolicies               // LockTag-scoped policies
///          │   ├── bytes12 lockTag                       // Lock tag identifier
///          │   └── PolicyData[] claimPolicies            // Claim policies array
///          │       ├── address policy                    // Policy address
///          │       └── bytes initData                    // Init data
///          │   bool permitGenericPolicy                  // Allow policy fallback
///          bytes32 salt,                                 // Unique salt value
///          address sessionValidator,                     // Validator contract address
///          bytes sessionValidatorInitData,               // Validator initialization data
///          address smartSessionEmissary                  // Smart Session Emissary address
///      )
bytes32 constant SESSION_TYPEHASH =
    0x984917e689987af96289e12c5f5e934fcdf1df4186108f69ff7e8c3df950ce33;

/// @dev ChainSession(uint64 chainId, SignedSession session)
bytes32 constant CHAIN_SESSION_TYPEHASH =
    0xabc350ff4773ba356e85e2d2ee58d7d7511767acdb108b59058f5b4a5afc074b;

/// @dev MultiChainSession(ChainSession[] sessionsAndChainIds)
bytes32 constant MULTICHAIN_SESSION_TYPEHASH =
    0xb4323194e4ca3723804b96dc7a0960bde1afff2b080b8b288fdc264c82e21357;

/// @dev keccak256("EIP712Domain(string name,string version)")
bytes32 constant _MULTICHAIN_DOMAIN_TYPEHASH =
    0xb03948446334eb9b2196d5eb166f69b9d49403eb4a12f36de8d3f9f3cb8e15c3;

/// @dev keccak256(abi.encode(
///          _MULTICHAIN_DOMAIN_TYPEHASH,
///          keccak256("SmartSessionEmissary"),
///          keccak256("1")
///      ))
bytes32 constant _MULTICHAIN_DOMAIN_SEPARATOR =
    0xe4b7e03cf1e8e7a6af0eec6f72a68d532e03fdaad0b8326461731cb31803a084;

/// @dev SignedPermissionDisable(
///          address account,                              // User account address
///          PermissionId permissionId,                    // Permission ID to disable
///          bytes12 lockTag,                              // Lock tag for the session
///          uint256 expires,                              // Expiration timestamp
///          uint256 nonce                                 // Nonce value
///      )
bytes32 constant SIGNED_PERMISSION_DISABLE_TYPEHASH =
    0x098b3120e60a8adc9d970dec9c1f8796974a3ab6154f995ad56ee7b9a38d8836;

/// @dev ChainDisable(uint64 chainId, SignedPermissionDisable disable)
bytes32 constant CHAIN_DISABLE_TYPEHASH =
    0x9e9bdba2de9bed6a73d19a18981bf116fe2fdb59357e77d23e8699b81267e5f6;

/// @dev MultiChainDisable(ChainDisable[] disablesAndChainIds)
bytes32 constant MULTICHAIN_DISABLE_TYPEHASH =
    0x6a9faa6216b7d82d297b22f3c509ce7c0148d5f4a342101e5026a65caaa845a2;

/// @title HashLibV2
/// @notice Extended version of HashLib from SmartSessions for the Emissary system
/// @dev Key differences from SmartSessions HashLib:
///      - lockTag scoped inside LockTagData (only affects claimPolicies)
///      - Removed: ignoreSecurityAttestations, permitAdminAccess, permitERC4337Paymaster,
///        userOpPolicies
///      - Added: expires, LockTagData (lockTag + claimPolicies)
library HashLibV2 {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using HashLibV2 for *;
    using HashLib for ActionData;
    using HashLib for PolicyData[];
    using HashLib for ERC7739Data;
    using EfficientHashLib for *;

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown when the provided chain ID does not match the current chain ID
    error ChainIdMismatch(uint64 providedChainId);

    /// @notice Thrown when the provided session digest does not match the computed digest
    error HashMismatch(bytes32 providedHash, bytes32 computedHash);

    /// @notice Thrown when an unsafe fallback action is attempted to be used
    error UnsafeFallbackNotAllowed();

    /*//////////////////////////////////////////////////////////////
                              LOCKTAG DATA
    //////////////////////////////////////////////////////////////*/

    /// @notice Hashes the LockTagData containing lockTag-scoped claim policies
    /// @dev The lockTag binds claim policies to a specific allocator context
    /// @param claimPolicies The claim policies to hash
    /// @param lockTag The lock tag derived from allocator + scope + resetPeriod
    /// @return The keccak256 hash of the encoded LockTagData
    function hashLockTagData(
        PolicyData[] memory claimPolicies,
        bytes12 lockTag
    )
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(LOCKTAG_DATA_TYPEHASH, lockTag, claimPolicies.hashPolicyDataArray())
        );
    }

    /*//////////////////////////////////////////////////////////////
                                SESSION
    //////////////////////////////////////////////////////////////*/

    /// @notice Computes the digest for a session based on the provided parameters
    /// @param session The session data to hash
    /// @param account The account address for which the session is being enabled
    /// @param nonce The nonce value for the session
    /// @param expires The expiration timestamp for the session
    /// @param lockTag The lock tag for the session (used in LockTagData hash)
    /// @return digest The computed digest for the session
    function _sessionDigest(
        Session memory session,
        address account,
        uint256 nonce,
        uint256 expires,
        bytes12 lockTag
    )
        internal
        view
        returns (bytes32 digest)
    {
        // chainId is not needed as it is in the ChainSession
        digest = keccak256(
            abi.encode(
                SESSION_TYPEHASH, // SignedSession
                account, // address account
                expires, // uint256 expires
                nonce, // uint256 nonce
                hashPermissions(session, lockTag), // SignedPermissions permissions
                session.salt, // bytes32 salt
                address(session.sessionValidator), // address sessionValidator
                keccak256(session.sessionValidatorInitData), // bytes sessionValidatorInitData
                address(this) // address smartSessionEmissary
            )
        );
    }

    /// @notice Public wrapper for _sessionDigest
    /// @param session The session data to hash
    /// @param account The account address for which the session is being enabled
    /// @param nonce The nonce value for the session
    /// @param expires The expiration timestamp for the session
    /// @param lockTag The lock tag for the session
    /// @return The computed session digest
    function sessionDigest(
        Session memory session,
        address account,
        uint256 nonce,
        uint256 expires,
        bytes12 lockTag
    )
        internal
        view
        returns (bytes32)
    {
        return _sessionDigest(session, account, nonce, expires, lockTag);
    }

    /// @notice Hashes the permissions data from a session
    /// @dev Combines action policies, ERC7739 policies, and lockTag-scoped claim policies
    /// @param session The session containing permissions data
    /// @param lockTag The lock tag to include in the LockTagData hash
    /// @return The keccak256 hash of the encoded permissions
    function hashPermissions(
        Session memory session,
        bytes12 lockTag
    )
        internal
        pure
        returns (bytes32)
    {
        (bool permitFallback, bytes32 actionDataArrayHash) = session.actions.hashActionDataArray();
        return keccak256(
            abi.encode(
                SIGNED_PERMISSIONS_TYPEHASH,
                actionDataArrayHash, // action policies
                session.erc7739Policies.hashERC7739Data(), // ERC7739 policies
                hashLockTagData(session.claimPolicies, lockTag), // LockTag-scoped claim policies
                permitFallback // bool permitGenericPolicy
            )
        );
    }

    /*//////////////////////////////////////////////////////////////
                                 ACTION
    //////////////////////////////////////////////////////////////*/

    /// @notice Hashes an array of ActionData structs
    /// @dev Also validates that unsafe fallback actions are not used
    /// @param actionDataArray The array of action data to hash
    /// @return permitFallback Whether a fallback action policy is present
    /// @return _hash The keccak256 hash of the encoded action data array
    function hashActionDataArray(ActionData[] memory actionDataArray)
        internal
        pure
        returns (bool permitFallback, bytes32 _hash)
    {
        uint256 length = actionDataArray.length;
        bytes32[] memory a = EfficientHashLib.malloc(length);

        for (uint256 i; i < length; i++) {
            ActionData memory actionData = actionDataArray[i];

            // Check if this action policy is a fallback action policy
            if (actionData.actionTarget == FALLBACK_TARGET_FLAG) {
                // Only set the permitFallbackFlag if not previously set to true
                permitFallback = permitFallback
                    || (actionData.actionTargetSelector == FALLBACK_TARGET_SELECTOR_FLAG);

                // Do not allow unsafe fallback actions in SmartSessionEmissary
                require(
                    actionData.actionTargetSelector
                        != FALLBACK_TARGET_SELECTOR_FLAG_PERMITTED_TO_CALL_SMARTSESSION,
                    UnsafeFallbackNotAllowed()
                );
            }

            a.set(i, actionData.hashActionData());
        }
        _hash = a.hash();
        a.free();
    }

    /*//////////////////////////////////////////////////////////////
                                DISABLE
    //////////////////////////////////////////////////////////////*/

    /// @notice Computes the digest for disabling a permission
    /// @param permissionId The ID of the permission to disable
    /// @param account The account address for which the permission is being disabled
    /// @param nonce The nonce value for the disable signature
    /// @param expires The expiration timestamp for the disable signature
    /// @param lockTag The lock tag for the session to disable
    /// @return digest The computed digest for the disable operation
    function disableDigest(
        PermissionId permissionId,
        address account,
        uint256 nonce,
        uint256 expires,
        bytes12 lockTag
    )
        internal
        pure
        returns (bytes32 digest)
    {
        digest = keccak256(
            abi.encode(
                SIGNED_PERMISSION_DISABLE_TYPEHASH, account, permissionId, lockTag, expires, nonce
            )
        );
    }

    /*//////////////////////////////////////////////////////////////
                               MULTICHAIN
    //////////////////////////////////////////////////////////////*/

    /// @notice Hashes a ChainDigest for RPC-compatible multichain signing
    /// @dev The sessionDigest is pre-computed off-chain and passed in
    /// @param chainDigest The chain digest containing chainId and pre-computed session digest
    /// @return The keccak256 hash of the encoded ChainSession
    function hashChainDigestMimicRPC(ChainDigest memory chainDigest)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(CHAIN_SESSION_TYPEHASH, chainDigest.chainId, chainDigest.sessionDigest)
        );
    }

    /// @notice Hashes an array of ChainDigest structs
    /// @param chainDigestArray The array of chain digests to hash
    /// @return The keccak256 hash of the encoded chain digest array
    function hashChainDigestArray(ChainDigest[] memory chainDigestArray)
        internal
        pure
        returns (bytes32)
    {
        uint256 length = chainDigestArray.length;

        bytes32[] memory a = EfficientHashLib.malloc(length);
        for (uint256 i; i < length; i++) {
            a.set(i, chainDigestArray[i].hashChainDigestMimicRPC());
        }
        return a.hash();
    }

    /// @notice Computes the final multichain digest for signing
    /// @dev Uses a chain-agnostic domain separator for cross-chain compatibility
    /// @param hashesAndChainIds Array of chain digests across all target chains
    /// @return The EIP-712 typed data hash for multichain signing
    function multichainDigest(ChainDigest[] memory hashesAndChainIds)
        internal
        pure
        returns (bytes32)
    {
        bytes32 structHash = keccak256(
            abi.encode(MULTICHAIN_SESSION_TYPEHASH, hashesAndChainIds.hashChainDigestArray())
        );

        return MessageHashUtils.toTypedDataHash(_MULTICHAIN_DOMAIN_SEPARATOR, structHash);
    }

    /// @notice Computes and verifies the session digest against provided chain data
    /// @dev Ensures the locally computed digest matches the signed digest for this chain
    /// @param enableData The EnableSession data containing session and chain digests
    /// @param account The account address for which the session is being enabled
    /// @param nonce The nonce value for the session
    /// @param expires The expiration timestamp for the session
    /// @param lockTag The lock tag for the session
    /// @return digest The computed multichain digest for signature verification
    function getAndVerifyDigest(
        EnableSession memory enableData,
        address account,
        uint256 nonce,
        uint256 expires,
        bytes12 lockTag
    )
        internal
        view
        returns (bytes32 digest)
    {
        bytes32 computedHash =
            enableData.sessionToEnable.sessionDigest(account, nonce, expires, lockTag);

        uint64 providedChainId = enableData.hashesAndChainIds[enableData.chainDigestIndex].chainId;
        bytes32 providedHash =
            enableData.hashesAndChainIds[enableData.chainDigestIndex].sessionDigest;

        if (providedChainId != block.chainid) {
            revert ChainIdMismatch(providedChainId);
        }

        // Ensure digest we've built from sessionToEnable matches the signed digest
        if (providedHash != computedHash) {
            revert HashMismatch(providedHash, computedHash);
        }

        digest = enableData.hashesAndChainIds.multichainDigest();
    }

    /// @notice Computes and verifies the disable digest against provided chain data
    /// @dev Ensures the locally computed digest matches the signed digest for this chain
    /// @param disableData The DisableSession data containing chainIds and digests
    /// @param permissionId The ID of the permission to disable
    /// @param account The account address for which the permission is being disabled
    /// @param nonce The nonce value for the disable signature
    /// @param expires The expiration timestamp for the disable signature
    /// @param lockTag The lock tag for the session to disable
    /// @return digest The computed multichain digest for signature verification
    function getAndVerifyDigest(
        DisableSession calldata disableData,
        PermissionId permissionId,
        address account,
        uint256 nonce,
        uint256 expires,
        bytes12 lockTag
    )
        internal
        view
        returns (bytes32 digest)
    {
        bytes32 computedHash = disableDigest(permissionId, account, nonce, expires, lockTag);

        uint64 providedChainId = disableData.hashesAndChainIds[disableData.chainDigestIndex].chainId;
        bytes32 providedHash =
            disableData.hashesAndChainIds[disableData.chainDigestIndex].sessionDigest;

        if (providedChainId != block.chainid) {
            revert ChainIdMismatch(providedChainId);
        }

        // Ensure digest we've built matches the signed digest
        if (providedHash != computedHash) {
            revert HashMismatch(providedHash, computedHash);
        }

        digest = disableData.hashesAndChainIds.multichainDigest();
    }
}
