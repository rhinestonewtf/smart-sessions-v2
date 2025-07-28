// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

// Interfaces
import { IStatelessValidator } from "@compact-utils/interfaces/IStatelessValidator.sol";

// Libraries
import { EfficientHashLib } from "@solady/utils/EfficientHashLib.sol";
import { HashLib } from "@smartsessions/lib/HashLib.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

// Types
import {
    SmartSessionMode,
    FALLBACK_TARGET_FLAG,
    FALLBACK_TARGET_SELECTOR_FLAG,
    FALLBACK_TARGET_SELECTOR_FLAG_PERMITTED_TO_CALL_SMARTSESSION,
    ChainDigest,
    ActionData,
    PolicyData,
    PermissionId
} from "@smartsessions/DataTypes.sol";
import { EnableSession, DisableSession, Session } from "@types/DataTypes.sol";

/*//////////////////////////////////////////////////////////////
                            TYPEHASHES
//////////////////////////////////////////////////////////////*/

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
 *     address sender                                    // Sender address
 * )
 */
bytes32 constant SESSION_TYPEHASH =
    0xdae0f31e2404f89c77eaca5b9c155d163e0a94c335466e03097d59ba66d902b1;

bytes32 constant SIGNED_PERMISSIONS_TYPEHASH =
    0x0f0c0a964a4d757ae7bbf96f0a509b39e4dc3cdb7417a69076093b8ed220756d;

// ChainSession(uint64 chainId,SignedSession session)
bytes32 constant CHAIN_SESSION_TYPEHASH =
    0xf1f832681cd52fd1bd0a179f6a440e1fa9cac028abdf4442fd1780f07779d857;

// MultiChainSession(ChainSession[] sessionsAndChainIds)
bytes32 constant MULTICHAIN_SESSION_TYPEHASH =
    0x5142bb6c62f0252495e84afe4340071576ef0f9aab524ab915e97000a5012478;

// keccak256("EIP712Domain(string name,string version)");
bytes32 constant _MULTICHAIN_DOMAIN_TYPEHASH =
    0xb03948446334eb9b2196d5eb166f69b9d49403eb4a12f36de8d3f9f3cb8e15c3;

// keccak256(abi.encode(_MULTICHAIN_DOMAIN_TYPEHASH,keccak256("SmartSessionEmissary"),
// keccak256("1")));
bytes32 constant _MULTICHAIN_DOMAIN_SEPARATOR =
    0xe4b7e03cf1e8e7a6af0eec6f72a68d532e03fdaad0b8326461731cb31803a084;

/*
 * SignedPermissionDisable(
 *     address account, // User account address
 *     PermissionId permissionId, // Permission ID to disable
 *     bytes12 lockTag, // Lock tag for the session
 *     address sender, // Sender address   
 *     uint256 expires, // Expiration timestamp
 *     uint256 nonce // Nonce value
 * )
*/
bytes32 constant SIGNED_PERMISSION_DISABLE_TYPEHASH =
    0xbe77f16494275ce0b6e48cb4bfa5492e513269b28d7e3db69722fc165f38345a;

// ChainDisable(uint64 chainId,SignedPermissionDisable disable)
bytes32 constant CHAIN_DISABLE_TYPEHASH =
    0x0efb04ccccc3ee314a40813c91dd0a97fa116a827af4767703b8f74697cb0831;

// MultiChainDisable(ChainDisable[] disablesAndChainIds)
bytes32 constant MULTICHAIN_DISABLE_TYPEHASH =
    0x0812907e4d4edbf1f5d71d2e93e0020f6fb5cd5edc9f44672ac70ae89efd1245;

/* 
 * SetConfig(
 *     address sponsor, // Sponsor address for the configuration
 *     address validator, // Stateless validator contract address
 *     uint8 configId, // Configuration ID for the emissary
 *     bytes12 lockTag, // Lock tag for the configuration
 *     uint256 expires, // Expiration timestamp for the configuration
 *     bytes validatorConfig, // Configuration data for the stateless validator
 *     uint256 nonce, // Nonce value for the configuration
 *     uint256[] chainIds // Array of chain IDs for which the configuration is valid
 * )
 */
bytes32 constant CONFIG_TYPEHASH =
    0x759a5fad79c46388b685ecbde4a995628d8ce7988bf4f85bbcac3dec1ed19ba2;

/// @dev An extended version of HashLib from SmartSessions that includes additional data from
///      emissary configurations when computing the session digest.
///
///      Added fields to the SignedSession struct:
///      - expires: uint256
///      - lockTag: bytes12
///      - sender: address
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
    /// @param sender The sender address for the session
    /// @return digest The computed digest for the session
    function _sessionDigest(
        Session memory session,
        address account,
        uint256 nonce,
        uint256 expires,
        bytes12 lockTag,
        address sender
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
                    sender // Sender address
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
        address sender
    )
        internal
        view
        returns (bytes32)
    {
        return _sessionDigest(session, account, nonce, expires, lockTag, sender);
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
    /// @param sender The sender address for the session to disable
    /// @return digest The computed digest for the session to disable
    function disableDigest(
        PermissionId permissionId,
        address account,
        uint256 nonce,
        uint256 expires,
        bytes12 lockTag,
        address sender
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
                sender, // Sender address
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
    /// @param sender The sender address for the session
    /// @return digest The computed multichain digest for the session
    function getAndVerifyDigest(
        EnableSession memory enableData,
        address account,
        uint256 nonce,
        uint256 expires,
        bytes12 lockTag,
        address sender
    )
        internal
        view
        returns (bytes32 digest)
    {
        bytes32 computedHash =
            enableData.sessionToEnable.sessionDigest(account, nonce, expires, lockTag, sender);

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
    /// @param sender The sender address for the session to disable
    function getAndVerifyDigest(
        DisableSession memory disableData,
        PermissionId permissionId,
        address account,
        uint256 nonce,
        uint256 expires,
        bytes12 lockTag,
        address sender
    )
        internal
        view
        returns (bytes32 digest)
    {
        bytes32 computedHash = disableDigest(permissionId, account, nonce, expires, lockTag, sender);

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

    /*//////////////////////////////////////////////////////////////
                             BASE EMISSARY
    //////////////////////////////////////////////////////////////*/

    /// @notice Computes the hash for a base emissary configuration
    /// @param sponsor The sponsor address for the configuration
    /// @param validator The stateless validator contract address
    /// @param configId The configuration ID for the emissary
    /// @param expires The expiration timestamp for the configuration
    /// @param lockTag The lock tag for the configuration
    /// @param nonce The nonce value for the configuration
    /// @param validatorConfig The configuration data for the stateless validator
    /// @param chainIds The array of chain IDs for which the configuration is valid
    /// @return hash The computed hash for the emissary configuration
    function hashConfig(
        address sponsor,
        IStatelessValidator validator,
        uint8 configId,
        uint256 expires,
        bytes12 lockTag,
        uint256 nonce,
        bytes calldata validatorConfig,
        uint256[] calldata chainIds
    )
        internal
        pure
        returns (bytes32 hash)
    {
        hash = keccak256(
            abi.encode(
                CONFIG_TYPEHASH,
                sponsor,
                validator,
                configId,
                lockTag,
                expires,
                keccak256(validatorConfig),
                nonce,
                keccak256(abi.encodePacked(chainIds))
            )
        );
    }
}
