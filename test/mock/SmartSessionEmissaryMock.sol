// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

// Contracts
import { SmartSessionEmissary } from "@contracts/SmartSessionEmissary.sol";
import { SmartSessionLens } from "@core/SmartSessionLens.sol";

// Interfaces
import { IStatelessValidator } from "@compact-utils/interfaces/IStatelessValidator.sol";

// Libraries
import { DigestCacheLib } from "@lib/DigestCacheLib.sol";
import { EnumerableSet } from "@smartsessions/utils/EnumerableSet4337.sol";
import { ConfigLib } from "@smartsessions/lib/ConfigLib.sol";
import { ConfigLibV2 } from "@lib/ConfigLibV2.sol";
import { IdLib } from "@smartsessions/lib/IdLib.sol";
import { IdLibV2 } from "@lib/IdLibV2.sol";
import { HashLibV2 } from "@lib/HashLibV2.sol";
import { PolicyLib } from "@smartsessions/lib/PolicyLib.sol";
import { PolicyLibV2 } from "@lib/PolicyLibV2.sol";
import { FlatBytesLib } from "@flatbytes/BytesLib.sol";
import { SignatureLib } from "@lib/SignatureLib.sol";

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
import { Session, NO_LOCKTAG } from "@types/DataTypes.sol";

/// @dev Extended SmartSessionEmissary with helpers for testing purposes.
contract SmartSessionEmissaryMock is SmartSessionEmissary {
    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown when the provided data is invalid
    error InvalidData();

    /*//////////////////////////////////////////////////////////////
                                LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using EnumerableSet for *;
    using ConfigLib for *;
    using ConfigLibV2 for *;
    using IdLib for *;
    using IdLibV2 for *;
    using HashLibV2 for *;
    using PolicyLib for *;
    using PolicyLibV2 for *;
    using FlatBytesLib for *;
    using SignatureLib for *;

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @notice Constructor to initialize the Smart Session Emissary Mock
    /// @param intentExecutor The address of the Intent Executor contract
    constructor(address intentExecutor)
        SmartSessionEmissary(intentExecutor, address(new SmartSessionLens()))
    { }

    /*//////////////////////////////////////////////////////////////
                           SESSION MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Enable multiple sessions with their associated policies
    function enableSessions(
        Session[] calldata sessions,
        bytes12 lockTag
    )
        external
        returns (PermissionId[] memory permissionIds)
    {
        return _enableSessions(sessions, msg.sender, lockTag);
    }

    /// TODO: CHECK IF THIS FUNCTION IS NEEDED ANYMORE
    /// @notice Enable multiple sessions with their associated policies
    /// @param sessions An array of Session structures to be enabled
    /// @param account The account address associated with the sessions
    /// @return permissionIds An array of PermissionId values corresponding to the enabled sessions
    function _enableSessions(
        Session[] calldata sessions,
        address account,
        bytes12 lockTag
    )
        internal
        returns (PermissionId[] memory permissionIds)
    {
        uint256 length = sessions.length;
        if (length == 0) revert InvalidData();

        permissionIds = new PermissionId[](length);

        for (uint256 i; i < length; i++) {
            Session calldata session = sessions[i];
            PermissionId permissionId = session.toPermissionId();

            // Enable ERC7739 content
            $enabledERC7739.enable({
                contexts: session.erc7739Policies.allowedERC7739Content,
                permissionId: permissionId, // TODO: Can we do this?
                account: account
            });

            // Enable ERC1271 policies
            $erc1271Policies.enable({
                policyType: PolicyType.ERC1271,
                permissionId: permissionId,
                configId: permissionId.toErc1271PolicyId().toConfigId(account),
                policyDatas: session.erc7739Policies.erc1271Policies,
                account: account
            });

            // Only enable claim and action policies if lockTag is not NO_LOCKTAG
            if (lockTag != NO_LOCKTAG) {
                // Enable claim policies
                $claimPolicies[lockTag].enable({
                    policyType: PolicyType.ERC1271,
                    permissionId: permissionId,
                    configId: permissionId.toErc1271PolicyId().toConfigId(account),
                    policyDatas: session.claimPolicies,
                    account: account
                });

                // Enable action policies
                $actionPolicies[lockTag].enable({
                    permissionId: permissionId, actionPolicyDatas: session.actions, account: account
                });

                // Add the lockTag to the enabled lockTags for the account
                $enabledLockTags.add({ account: account, value: bytes32(lockTag) });
            }

            // Enable the ISessionValidator for this session
            if (!_isISessionValidatorSet(permissionId, account)) {
                $sessionValidators.enable({
                    permissionId: permissionId,
                    sessionValidator: session.sessionValidator,
                    sessionValidatorConfig: session.sessionValidatorInitData,
                    account: account
                });
            }
            permissionIds[i] = permissionId;

            // Add to enabled sessions
            $enabledSessions.add({ account: account, value: PermissionId.unwrap(permissionId) });
        }
    }

    /*//////////////////////////////////////////////////////////////
                        TEST HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /*//////////////////////////////////////////////////////////////
                        CACHE HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

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
