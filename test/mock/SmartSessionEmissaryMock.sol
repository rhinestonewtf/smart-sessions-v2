// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import { SmartSessionEmissary } from "@contracts/SmartSessionEmissary.sol";

// Interfaces
import { IStatelessValidator } from "@compact-utils/interfaces/IStatelessValidator.sol";

// Libraries
import { Compressed } from "@compact-utils/common/CompressedStorageLib.sol";
import { DigestCacheLib } from "@lib/DigestCacheLib.sol";

// Types
import {
    PermissionId,
    ActionId,
    ActionData,
    SignerConf,
    EnumerableActionPolicy,
    PolicyType,
    EMPTY_PERMISSIONID,
    Policy
} from "@smartsessions/DataTypes.sol";
import { Session } from "@types/DataTypes.sol";

/// @dev Extended SmartSessionEmissary with helpers for testing purposes.
contract SmartSessionEmissaryMock is SmartSessionEmissary {
    /* //////////////////////////////////////////////////////////////
                                LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using Compressed for *;

    /* //////////////////////////////////////////////////////////////
                           SESSION MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Enable multiple sessions with their associated policies
    function enableSessions(Session[] calldata sessions, bytes12 lockTag, address sender)
        external
        returns (PermissionId[] memory permissionIds)
    {
        return _enableSessions(sessions, msg.sender, true, lockTag, sender);
    }

    /* //////////////////////////////////////////////////////////////
                        TEST HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Helper to set up stateless validator config for testing
    function setupStatelessValidatorConfig(
        address account,
        uint8 configId,
        bytes12 lockTag,
        IStatelessValidator validator,
        bytes memory validatorConfig
    )
        external
    {
        $statelessValidatorConfig[account][configId][lockTag][validator].sstore(validatorConfig);
    }

    /// @notice Helper to set up ECDSA config for testing
    function setupECDSAConfig(
        address account,
        uint8 configId,
        bytes12 lockTag,
        uint256 threshold,
        address[] memory owners
    )
        external
    {
        bytes memory configData = abi.encode(threshold, owners);
        $ecdsaPasskeyConfig[account][configId][lockTag].sstore(configData);
    }

    /// @notice Helper to set up Passkey config for testing
    function setupPasskeyConfig(
        address account,
        uint8 configId,
        bytes12 lockTag,
        bytes memory passkeyConfigData
    )
        external
    {
        $ecdsaPasskeyConfig[account][configId][lockTag].sstore(passkeyConfigData);
    }

    /* //////////////////////////////////////////////////////////////
                        CACHE HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Check if ECDSA digest is cached
    function isDigestCachedECDSA(address account, bytes32 digest, uint8 configId, bytes12 lockTag)
        external
        view
        returns (bool)
    {
        return DigestCacheLib.isAlreadyVerified(digest, account, configId, lockTag);
    }

    /// @notice Set ECDSA digest cache
    function setDigestCacheECDSA(address account, bytes32 digest, uint8 configId, bytes12 lockTag)
        external
    {
        DigestCacheLib.markAsVerified(digest, account, configId, lockTag);
    }

    /// @notice Check if Stateless Validator digest is cached
    function isDigestCachedStateless(
        address account,
        bytes32 digest,
        address validator,
        uint8 configId,
        bytes12 lockTag
    )
        external
        view
        returns (bool)
    {
        return DigestCacheLib.isAlreadyVerified(
            digest, account, IStatelessValidator(validator), configId, lockTag
        );
    }

    /// @notice Set Stateless Validator digest cache
    function setDigestCacheStateless(
        address account,
        bytes32 digest,
        address validator,
        uint8 configId,
        bytes12 lockTag
    )
        external
    {
        DigestCacheLib.markAsVerified(
            digest, account, IStatelessValidator(validator), configId, lockTag
        );
    }

    /// @notice Check if SmartSession digest is cached
    function isDigestCachedSmartSession(
        address account,
        bytes32 digest,
        PermissionId permissionId,
        bytes12 lockTag
    )
        external
        view
        returns (bool)
    {
        return DigestCacheLib.isAlreadyVerified(digest, account, permissionId, lockTag);
    }

    /// @notice Set SmartSession digest cache
    function setDigestCacheSmartSession(
        address account,
        bytes32 digest,
        PermissionId permissionId,
        bytes12 lockTag
    )
        external
    {
        DigestCacheLib.markAsVerified(digest, account, permissionId, lockTag);
    }

    /// @notice Clear ECDSA digest cache
    function clearDigestCacheECDSA(address account, bytes32 digest, uint8 configId, bytes12 lockTag)
        external
    {
        bytes32 slot;
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, 0x468e535faa4b0ffe3d06) // TSTORE_BASE_SLOT
            mstore(add(ptr, 0x20), account)
            mstore(add(ptr, 0x40), digest)
            mstore(add(ptr, 0x60), configId)
            mstore(add(ptr, 0x80), lockTag)
            slot := keccak256(ptr, 0xa0)
            tstore(slot, 0)
        }
    }

    /// @notice Clear Stateless Validator digest cache
    function clearDigestCacheStateless(
        address account,
        bytes32 digest,
        address validator,
        uint8 configId,
        bytes12 lockTag
    )
        external
    {
        bytes32 slot;
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, 0x468e535faa4b0ffe3d06)
            mstore(add(ptr, 0x20), account)
            mstore(add(ptr, 0x40), digest)
            mstore(add(ptr, 0x60), validator)
            mstore(add(ptr, 0x80), configId)
            mstore(add(ptr, 0xa0), lockTag)
            slot := keccak256(ptr, 0xc0)
            tstore(slot, 0)
        }
    }

    /// @notice Clear SmartSession digest cache
    function clearDigestCacheSmartSession(
        address account,
        bytes32 digest,
        PermissionId permissionId,
        bytes12 lockTag
    )
        external
    {
        bytes32 slot;
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, 0x468e535faa4b0ffe3d06)
            mstore(add(ptr, 0x20), account)
            mstore(add(ptr, 0x40), digest)
            mstore(add(ptr, 0x60), permissionId)
            mstore(add(ptr, 0x80), lockTag)
            slot := keccak256(ptr, 0xa0)
            tstore(slot, 0)
        }
    }
}
