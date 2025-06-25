// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

// Libraries
import { EfficientHashLib } from "@solady/utils/EfficientHashLib.sol";
import { HashLib } from "@smartsessions/lib/HashLib.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

// Types
import {
    SmartSessionMode,
    ActionData,
    PolicyData,
    FALLBACK_TARGET_FLAG,
    FALLBACK_TARGET_SELECTOR_FLAG,
    FALLBACK_TARGET_SELECTOR_FLAG_PERMITTED_TO_CALL_SMARTSESSION,
    ChainDigest,
    PermissionId
} from "@smartsessions/DataTypes.sol";
import { EnableSession, DisableSession, Session } from "@types/DataTypes.sol";

/*//////////////////////////////////////////////////////////////
                            TYPEHASHES
//////////////////////////////////////////////////////////////*/

// forgefmt: disable-next-item
/*
 * SignedSession(
 *     address account,                                  // User account address
 *     SignedPermissions permissions,                    // Signed permissions struct
 *     │   bool  permitGenericPolicy,                    // Allow policy fallback
 *     │   PolicyData[] erc1271Policies                  // ERC1271 policies array
 *     │   ├── address policy                            // Policy address
 *     │   └── bytes initData                            // Init data
 *     │   ActionData[] actions                          // Actions array
 *     │   ├── bytes4 actionTargetSelector               // Function selector
 *     │   ├── address actionTarget                      // Target contract
 *     │   └── PolicyData[] actionPolicies               // Action policies array
 *     │       ├── address policy                        // Policy address
 *     │       └── bytes initData                        // Init data
 *     address sessionValidator,                         // Validator contract address
 *     bytes sessionValidatorInitData,                   // Validator initialization data
 *     bytes32 salt,                                     // Unique salt value
 *     address smartSessionEmissary,                     // Smart Session Emissary contract address
 *     uint256 nonce                                     // Nonce value
 *     uint256 expires,                                  // Expiration timestamp
 *     bytes12 lockTag,                                  // Lock tag for the session
 *     address arbiter,                                  // Arbiter address
 *     address allocator                                 // Allocator address
 * )
 */
bytes32 constant SESSION_TYPEHASH =
    0xd44896e3cb83d70abc949a38dd6f9f75e675dc329dfe958617f066f79ff88f05; // TODO: Recalculate this
    // hash
bytes32 constant SIGNED_PERMISSIONS_TYPEHASH =
    0x871289c05e426554eb0f843c9aa542f9c2bc4eba7742ada6a5c014d3568674d4; // TODO: Recalculate this hash

// ChainSession(uint64 chainId,SignedSession session)
bytes32 constant CHAIN_SESSION_TYPEHASH =
    0x1ea7e4bc398fa0ccd68d92b5d8931a3fd93eebe1cf0391b4ba28935801af7c80; // TODO: Recalculate this hash

// MultiChainSession(ChainSession[] sessionsAndChainIds)
bytes32 constant MULTICHAIN_SESSION_TYPEHASH =
    0x0c9d02fb89a1da34d66ea2088dc9ee6a58efee71cef6f1bb849ed74fc6003d98; // TODO: Recalculate this hash

// keccak256("EIP712Domain(string name,string version)");
bytes32 constant _MULTICHAIN_DOMAIN_TYPEHASH =
    0xb03948446334eb9b2196d5eb166f69b9d49403eb4a12f36de8d3f9f3cb8e15c3; // TODO: Recalculate this hash

// keccak256(abi.encode(_MULTICHAIN_DOMAIN_TYPEHASH, keccak256("SmartSessionEmissary"),
// keccak256("1")));
bytes32 constant _MULTICHAIN_DOMAIN_SEPARATOR =
    0x057501e891776d1482927e5f094ae44049a4d893ba2d7b334dd7db8d38d3a0e1; // TODO: Recalculate this hash

// forgefmt: disable-next-item
/*
 * SignedPermissionDisable(
 *     address account, // User account address
 *     PermissionId permissionId, // Permission ID to disable
 *     bytes12 lockTag, // Lock tag for the session
 *     address arbiter, // Arbiter address   
 *     address allocator, // Allocator address
 *     uint256 expires, // Expiration timestamp
 *     uint256 nonce // Nonce value
 * )
*/

bytes32 constant SIGNED_PERMISSION_DISABLE_TYPEHASH =
    0xd44896e3cb83d70abc949a38dd6f9f75e675dc329dfe958617f066f79ff88f05; // TODO: Recalculate this
    // hash

// ChainDisable(uint64 chainId, SignedPermissionDisable disable)
bytes32 constant CHAIN_DISABLE_TYPEHASH =
    0x1ea7e4bc398fa0ccd68d92b5d8931a3fd93eebe1cf0391b4ba28935801af7c80; // TODO: Recalculate this hash
// MultiChainDisable(ChainDisable[] disablesAndChainIds)
bytes32 constant MULTICHAIN_DISABLE_TYPEHASH =
    0x0c9d02fb89a1da34d66ea2088dc9ee6a58efee71cef6f1bb849ed74fc6003d98; // TODO: Recalculate this hash

/// @dev An extended version of HashLib from SmartSessions that includes additional data from
///      emissary configurations when computing the session digest.
///
///      Added fields to the SignedSession struct:
///      - expires: uint256
///      - lockTag: bytes12
///      - arbiter: address
///      - allocator: address
///      Removed fields from the SignedSession struct:
///      - ignoreSecurityAttestations: bool
///      - permitAdminAccess: bool
///      - permitERC4337Paymaster: bool
///      - userOpPolicies: PolicyData[]
//       - erc7739Policies: ERC7739Data (the nested erc1271Policies field has been kept)
library HashLibV2 {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using HashLibV2 for *;
    using HashLib for ActionData;
    using HashLib for PolicyData[];
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
                                SESSION
    //////////////////////////////////////////////////////////////*/

    /// @notice Computes the digest for a session based on the provided parameters
    /// @param account The account address for which the session is being enabled
    /// @param nonce The nonce value for the session
    /// @param expires The expiration timestamp for the session
    /// @param lockTag The lock tag for the session
    /// @param arbiter The arbiter address for the session
    /// @param allocator The allocator address for the session
    /// @return digest The computed digest for the session
    function _sessionDigest(
        Session memory session,
        address account,
        uint256 nonce,
        uint256 expires,
        bytes12 lockTag,
        address arbiter,
        address allocator
    )
        internal
        view
        returns (bytes32 digest)
    {
        {
            // chainId is not needed as it is in the ChainSession
            digest = keccak256(
                abi.encode(
                    SESSION_TYPEHASH, // Typehash for the SignedSession struct
                    account, // User account address (sponsor)
                    hashPermissions(session), // Hashed permissions data
                    address(session.sessionValidator), // Validator contract address
                    keccak256(session.sessionValidatorInitData), // Validator initialization data
                    session.salt, // Session salt
                    address(this), // Smart Session Emissary contract address
                    nonce, // Session nonce
                    expires, // Expiration timestamp
                    lockTag, // Lock tag for the session
                    arbiter, // Arbiter address
                    allocator // Allocator address
                )
            );
        }
    }

    /// @dev Adjusted sessionDigest function to work with the new Session type
    function sessionDigest(
        Session memory session,
        address account,
        uint256 nonce,
        uint256 expires,
        bytes12 lockTag,
        address arbiter,
        address allocator
    )
        internal
        view
        returns (bytes32)
    {
        return _sessionDigest(session, account, nonce, expires, lockTag, arbiter, allocator);
    }

    /// @dev Adjusted hashPermissions function to exclude unused fields from SmartSessions
    function hashPermissions(Session memory session) internal pure returns (bytes32) {
        (bool permitFallback, bytes32 actionDataArrayHash) = session.actions.hashActionDataArray();
        return keccak256(
            abi.encode(
                SIGNED_PERMISSIONS_TYPEHASH,
                permitFallback, // permitGenericPolicy
                session.erc1271Policies.hashPolicyDataArray(), // erc1271Policies
                actionDataArrayHash // actions
            )
        );
    }

    /*//////////////////////////////////////////////////////////////
                                 ACTION
    //////////////////////////////////////////////////////////////*/

    /// @dev Adjusted hashActionDataArray function to only include relevant fields
    function hashActionDataArray(ActionData[] memory actionDataArray)
        internal
        pure
        returns (bool permitFallback, bytes32 _hash)
    {
        uint256 length = actionDataArray.length;
        bytes32[] memory a = EfficientHashLib.malloc(length);

        for (uint256 i; i < length; i++) {
            ActionData memory actionData = actionDataArray[i];
            // if this action policy is a fallback action policy
            if (actionData.actionTarget == FALLBACK_TARGET_FLAG) {
                // only set the permitFallbackFlag if not previously set to true
                permitFallback = permitFallback
                    || (actionData.actionTargetSelector == FALLBACK_TARGET_SELECTOR_FLAG);

                // Do not allow unsafe fallback actions to be used in SmartSessionEmissary
                require(
                    actionData.actionTargetSelector
                        != FALLBACK_TARGET_SELECTOR_FLAG_PERMITTED_TO_CALL_SMARTSESSION,
                    UnsafeFallbackNotAllowed()
                );
            }

            a.set(i, actionData.hashActionData());
        }
        _hash = a.hash();
    }

    /*//////////////////////////////////////////////////////////////
                                DISABLE
    //////////////////////////////////////////////////////////////*/

    /// @notice Computes the digest for disabling a permission
    /// @param permissionId The ID of the permission to disable
    /// @param account The account address for which the permission is being disabled
    /// @param nonce The nonce value for the disable signature
    /// @param expires The expiration timestamp for the disable signature
    /// @param lockTag The lock tag for session to disable
    /// @param arbiter The arbiter address for the session to disable
    /// @param allocator The allocator address for the session to disable
    /// @return digest The computed digest for the session to disable
    function disableDigest(
        PermissionId permissionId,
        address account,
        uint256 nonce,
        uint256 expires,
        bytes12 lockTag,
        address arbiter,
        address allocator
    )
        internal
        pure
        returns (bytes32 digest)
    {
        digest = keccak256(
            abi.encode(
                SIGNED_PERMISSION_DISABLE_TYPEHASH, // Typehash for the SignedPermissionDisable
                    // struct
                account, // User account address (sponsor)
                permissionId, // Permission ID to disable
                lockTag, // Lock tag for the session
                arbiter, // Arbiter address
                allocator, // Allocator address
                expires, // Expiration timestamp
                nonce // Nonce value
            )
        );
    }

    /*//////////////////////////////////////////////////////////////
                               MULTICHAIN
    //////////////////////////////////////////////////////////////*/

    /// @dev Imported from SmartSessions, but uses new typehash because the fields are different
    function hashChainDigestMimicRPC(ChainDigest memory chainDigest)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                CHAIN_SESSION_TYPEHASH,
                chainDigest.chainId,
                chainDigest.sessionDigest // this is the digest obtained using sessionDigest()
                    // we just do not rebuild it here for all sessions, but receive it from
                    // off-chain
            )
        );
    }

    /// @dev Imported from SmartSessions, but uses new typehash because the fields are different
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

    /// @dev Imported from SmartSessions, but uses new typehash because the fields are different
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

    /// @notice Computes the digest for a session and verifies it against the provided data
    /// @param enableData The EnableSession data containing the session and chain digests
    /// @param account The account address for which the session is being enabled
    /// @param nonce The nonce value for the session
    /// @param expires The expiration timestamp for the session
    /// @param lockTag The lock tag for the session
    /// @param arbiter The arbiter address for the session
    /// @param allocator The allocator address for the session
    /// @return digest The computed multichain digest for the session
    function getAndVerifyDigest(
        EnableSession memory enableData,
        address account,
        uint256 nonce,
        uint256 expires,
        bytes12 lockTag,
        address arbiter,
        address allocator
    )
        internal
        view
        returns (bytes32 digest)
    {
        bytes32 computedHash = enableData.sessionToEnable.sessionDigest(
            account, nonce, expires, lockTag, arbiter, allocator
        );

        uint64 providedChainId = enableData.hashesAndChainIds[enableData.chainDigestIndex].chainId;
        bytes32 providedHash =
            enableData.hashesAndChainIds[enableData.chainDigestIndex].sessionDigest;

        if (providedChainId != block.chainid) {
            revert ChainIdMismatch(providedChainId);
        }

        // ensure digest we've built from the sessionToEnable is included into
        // the list of digests that were signed
        if (providedHash != computedHash) {
            revert HashMismatch(providedHash, computedHash);
        }

        digest = enableData.hashesAndChainIds.multichainDigest();
    }

    /// @notice Computes the digest for disable data and verifies it against the provided data
    /// @param disableData The DisableSession data containing the chainIds and digests
    /// @param permissionId The ID of the permission to disable
    /// @param account The account address for which the permission is being disabled
    /// @param nonce The nonce value for the disable signature
    /// @param expires The expiration timestamp for the disable signature
    /// @param lockTag The lock tag for the session to disable
    /// @param arbiter The arbiter address for the session to disable
    /// @param allocator The allocator address for the session to disable
    function getAndVerifyDigest(
        DisableSession memory disableData,
        PermissionId permissionId,
        address account,
        uint256 nonce,
        uint256 expires,
        bytes12 lockTag,
        address arbiter,
        address allocator
    )
        internal
        view
        returns (bytes32 digest)
    {
        bytes32 computedHash =
            disableDigest(permissionId, account, nonce, expires, lockTag, arbiter, allocator);

        uint64 providedChainId = disableData.hashesAndChainIds[disableData.chainDigestIndex].chainId;
        bytes32 providedHash =
            disableData.hashesAndChainIds[disableData.chainDigestIndex].sessionDigest;

        if (providedChainId != block.chainid) {
            revert ChainIdMismatch(providedChainId);
        }

        // ensure digest we've built from the sessionToEnable is included into
        // the list of digests that were signed
        if (providedHash != computedHash) {
            revert HashMismatch(providedHash, computedHash);
        }

        digest = disableData.hashesAndChainIds.multichainDigest();
    }
}
