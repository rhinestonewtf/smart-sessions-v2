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
import {
    LOCKTAG_DATA_TYPEHASH,
    SESSION_TYPEHASH,
    SIGNED_PERMISSIONS_TYPEHASH,
    SIGNED_PERMISSION_DISABLE_TYPEHASH,
    CHAIN_SESSION_TYPEHASH,
    MULTICHAIN_SESSION_TYPEHASH,
    _MULTICHAIN_DOMAIN_SEPARATOR,
    HashLibV2
} from "@lib/HashLibV2.sol";

/// @title HashLibV2Calldata
/// @dev Calldata version of HashLibV2, all functions should 1-1 mirror those in HashLibV2 except
///        they accept calldata structs/arrays
library HashLibV2Calldata {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using HashLibV2Calldata for *;
    using HashLib for ActionData;
    using HashLib for PolicyData[];
    using HashLib for ERC7739Data;
    using EfficientHashLib for *;

    /*//////////////////////////////////////////////////////////////
                              LOCKTAG DATA
    //////////////////////////////////////////////////////////////*/

    /// @notice Hashes the LockTagData containing lockTag-scoped claim policies
    /// @dev The lockTag binds claim policies to a specific allocator context
    /// @param claimPolicies The claim policies to hash
    /// @param lockTag The lock tag derived from allocator + scope + resetPeriod
    /// @return The keccak256 hash of the encoded LockTagData
    function hashLockTagData(
        PolicyData[] calldata claimPolicies,
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
        Session calldata session,
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
        Session calldata session,
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
        Session calldata session,
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
    function hashActionDataArray(ActionData[] calldata actionDataArray)
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
                    HashLibV2.UnsafeFallbackNotAllowed()
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
    function hashChainDigestMimicRPC(ChainDigest calldata chainDigest)
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
    function hashChainDigestArray(ChainDigest[] calldata chainDigestArray)
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
    function multichainDigest(ChainDigest[] calldata hashesAndChainIds)
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
        EnableSession calldata enableData,
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
            revert HashLibV2.ChainIdMismatch(providedChainId);
        }

        // Ensure digest we've built from sessionToEnable matches the signed digest
        if (providedHash != computedHash) {
            revert HashLibV2.HashMismatch(providedHash, computedHash);
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
            revert HashLibV2.ChainIdMismatch(providedChainId);
        }

        // Ensure digest we've built matches the signed digest
        if (providedHash != computedHash) {
            revert HashLibV2.HashMismatch(providedHash, computedHash);
        }

        digest = disableData.hashesAndChainIds.multichainDigest();
    }
}
