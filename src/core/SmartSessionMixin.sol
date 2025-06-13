// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Contracts
import { SmartSessionManager } from "@core/SmartSessionManager.sol";
import { SmartSessionERC7739 } from "@core/SmartSessionERC7739.sol";

// Interfaces
import { IERC7579Account } from "erc7579/interfaces/IERC7579Account.sol";

// Libraries
import { EncodeLib } from "@smartsessions/lib/EncodeLib.sol";
import { SmartSessionModeLib } from "@smartsessions/lib/SmartSessionModeLib.sol";
import { IdLib } from "@smartsessions/lib/IdLib.sol";
import { EnumerableSet } from "@smartsessions/utils/EnumerableSet4337.sol";
import { ExecutionLib } from "@smartsessions/lib/ExecutionLib.sol";
import { PolicyLibV2 } from "@lib/PolicyLibV2.sol";
import { PolicyLib } from "@smartsessions/lib/PolicyLib.sol";
import { SignerLib } from "@smartsessions/lib/SignerLib.sol";
import { HashLib } from "@smartsessions/lib/HashLib.sol";
import { ConfigLibV2 } from "@lib/ConfigLibV2.sol";
import { IdLib as CompactIdLib } from "@the-compact/lib/IdLib.sol";
import { EIP712Hash } from "@lib/EIP712Hash.sol";
import { SignatureCheckerLib } from "@solady/utils/SignatureCheckerLib.sol";

// Types
import {
    PermissionId, SmartSessionMode, EnableSession, Session
} from "@smartsessions/DataTypes.sol";
import { SmartSessionEmissaryConfig, EmissaryEnable } from "@interfaces/ISmartSessionEmissary.sol";
import {
    ExecType,
    CallType,
    CALLTYPE_BATCH,
    CALLTYPE_SINGLE,
    EXECTYPE_DEFAULT
} from "erc7579/lib/ModeLib.sol";

/// @title SmartSessionMixin
/// @notice Mixin providing SmartSession functionality for emissaries
/// @dev Bridges lockTag-based emissary system with permissionId-based SmartSession system
abstract contract SmartSessionMixin is SmartSessionManager, SmartSessionERC7739 {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using EncodeLib for *;
    using SmartSessionModeLib for *;
    using IdLib for *;
    using EnumerableSet for *;
    using ExecutionLib for *;
    using PolicyLib for *;
    using PolicyLibV2 for *;
    using SignerLib for *;
    using HashLib for *;
    using ConfigLibV2 for *;
    using CompactIdLib for address;
    using CompactIdLib for bytes12;
    using CompactIdLib for uint96;
    using SignatureCheckerLib for address;

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Maps lockTag to enabled permissionIds for verifyClaim lookups
    /// @dev Bridge storage connecting emissary lockTags to SmartSession permissionIds
    mapping(address sender => mapping(bytes12 lockTag => EnumerableSet.Bytes32Set PermissionIDs))
        internal $smartSessionConfig;

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
        bytes12 lockTag =
            config.allocator.toAllocatorId().toLockTag(config.scope, config.resetPeriod);

        // Nonce validation to prevent replay attacks
        uint256 nonce = enableData.nonce;
        uint256 currentNonce = $emissaryNonce[account][lockTag];
        require(nonce > currentNonce, InvalidNonce());
        $emissaryNonce[account][lockTag] = nonce;

        // Verify chain ID matches current chain
        require(
            enableData.allChainIds[enableData.chainIndex] == block.chainid,
            InvalidEmissaryEnableData()
        );
        // Verify data expires after current block timestamp
        require(enableData.expires > block.timestamp, InvalidEmissaryEnableData());
        // Calculate EIP-712 hash for configuration
        bytes32 hash = EIP712Hash.config({
            sponsor: account,
            lockTag: lockTag,
            expires: enableData.expires,
            sessions: config.sessions,
            nonce: nonce,
            chainIds: enableData.allChainIds
        });
        // Hash the typed data structure (excluding chainId as it's implicitly checked)
        bytes32 digest = _getTypedDataHashSansChainId(hash);

        // Verify user signature
        if (msg.sender != account) {
            require(
                account.isValidSignatureNowCalldata(digest, enableData.userSig),
                InvalidUserSignature()
            );
        }
        // Verify allocator signature
        require(
            config.allocator.isValidERC1271SignatureNowCalldata(digest, enableData.allocatorSig),
            InvalidAllocatorSignature()
        );

        // TODO: This is ass placeholder

        // Get all enabled permissionIds
        address sender = config.arbiter;
        bytes32[] memory enabledPermissionIds = $smartSessionConfig[sender][lockTag].values(account);

        // Remove existing sessions for this lockTag and arbiter
        $smartSessionConfig[sender][lockTag].removeAll(account);

        // Call remove session for each existing permissionId
        for (uint256 i; i < enabledPermissionIds.length; i++) {
            PermissionId permissionId = PermissionId.wrap(enabledPermissionIds[i]);
            _removeSession(permissionId, account);
        }

        //  Enable new sessions if provided
        if (config.sessions.length != 0) {
            PermissionId[] memory permissionIDs = _enableSessions(config.sessions, account, true);
            // Map returned permissionIds to lockTag in smartSessionConfig
            for (uint256 i; i < permissionIDs.length; i++) {
                $smartSessionConfig[sender][lockTag].add(
                    account, PermissionId.unwrap(permissionIDs[i])
                );
                // Emit event for each enabled session
                emit SmartSessionEmissaryConfigUpdated(account, permissionIDs[i], lockTag);
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                                 CLAIM
    //////////////////////////////////////////////////////////////*/

    /// @notice Verifies claims using SmartSession (mode 2)
    /// @param sponsor The sponsor account associated with the claim
    /// @param claimHash The hash of the claim being verified
    /// @param emissaryData Data containing the permissionId and ERC-7739 signature
    /// @param lockTag The lock tag associated with the claim
    /// @return result The verifyClaim selector if valid, otherwise 0xffffffff
    function _verifyClaimSmartSession(
        address sponsor,
        bytes32 claimHash,
        bytes calldata emissaryData,
        bytes12 lockTag
    )
        internal
        view
        virtual
        returns (bytes4 result)
    {
        bool success = _erc1271IsValidSignatureViaNestedEIP712(
            msg.sender, claimHash, _erc1271UnwrapSignature(emissaryData), sponsor, lockTag
        );
        /// @solidity memory-safe-assembly
        assembly {
            // `success ? bytes4(keccak256("verifyClaim(address,bytes32,bytes32,bytes,bytes12)")) :
            // 0xffffffff`.
            result := shl(224, or(0xf699ba1c, sub(0, iszero(success))))
        }
    }

    /*//////////////////////////////////////////////////////////////
                               EXECUTION
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
        internal
        virtual
        returns (bytes4)
    {
        // Init validSig
        bool validSig;

        // unpacking data packed in data
        (SmartSessionMode mode, PermissionId permissionId, bytes calldata packedSig) =
            emissaryData.unpackMode();

        // If the SmartSession.USE mode was selected, no further policies have to be enabled.
        // We can go straight to userOp validation
        // This condition is the average case, so should be handled as the first condition
        if (mode.isUseMode()) {
            // USE mode: Directly enforce policies without enabling new ones
            validSig = _enforcePolicies({
                permissionId: permissionId,
                hash: hash,
                callData: executions,
                decompressedSignature: packedSig,
                account: account
            });
        }
        // if an Unknown mode is provided, the function will revert
        else {
            revert UnsupportedSmartSessionMode(mode);
        }

        // Return the function selector on success, or a specific failure code otherwise.
        return validSig ? this.verifyExecution.selector : bytes4(0xffffffff);
    }

    /*//////////////////////////////////////////////////////////////
                                INTERNAL
    //////////////////////////////////////////////////////////////*/

    /// @notice Enforces policies and checks ISessionValidator signature for a session
    /// @dev This function is the core of policy enforcement in SmartSession
    /// @param permissionId The unique identifier for the permission set
    /// @param hash Message hash to be validated
    /// @param callData Execution data for the call
    /// @param decompressedSignature The decompressed signature for validation
    /// @param account The account for which policies are being enforced
    /// @return validSig True if the signature is valid, false otherwise
    function _enforcePolicies(
        PermissionId permissionId,
        bytes32 hash,
        bytes calldata callData,
        bytes memory decompressedSignature,
        address account
    )
        internal
        returns (bool validSig)
    {
        // ensure that the permissionId is enabled
        if (
            !$enabledSessions.contains({ account: account, value: PermissionId.unwrap(permissionId) })
        ) {
            revert InvalidPermissionId(permissionId);
        }
        bytes4 selector = bytes4(callData[0:4]);

        /*//////////////////////////////////////////////////////////////
                                HANDLE EXECUTIONS
        //////////////////////////////////////////////////////////////*/

        // if the selector indicates that the userOp is an execution,
        // action policies have to be checked
        if (selector == IERC7579Account.execute.selector) {
            // Decode ERC7579 execution mode
            (CallType callType, ExecType execType) = callData.get7579ExecutionTypes();
            // ERC7579 allows for different execution types, but SmartSession only supports the
            // default execution type
            if (ExecType.unwrap(execType) != ExecType.unwrap(EXECTYPE_DEFAULT)) {
                revert UnsupportedExecutionType();
            }
            // DEFAULT EXEC & BATCH CALL
            else if (callType == CALLTYPE_BATCH) {
                $actionPolicies.actionPolicies.checkBatch7579Exec({
                    callData: callData,
                    permissionId: permissionId,
                    minPolicies: 1, // minimum of one actionPolicy must be set.
                    account: account
                });
            }
            // DEFAULT EXEC & SINGLE CALL
            else if (callType == CALLTYPE_SINGLE) {
                (address target, uint256 value, bytes calldata decodedCallData) =
                    callData.decodeUserOpCallData().decodeSingle();
                $actionPolicies.actionPolicies.checkSingle7579Exec({
                    permissionId: permissionId,
                    target: target,
                    value: value,
                    callData: decodedCallData,
                    minPolicies: 1, // minimum of one actionPolicy must be set.
                    account: account
                });
            }
            // DelegateCalls are not supported by SmartSessionExecutionVerifier
            else {
                revert UnsupportedExecutionType();
            }
        }
        // All other executions are not supported
        else {
            revert UnsupportedSelector();
        }

        /*//////////////////////////////////////////////////////////////
                                CHECK SESSION KEY
        //////////////////////////////////////////////////////////////*/

        // perform signature check with ISessionValidator
        // this function will revert if no ISessionValidator is set for this permissionId
        validSig = $sessionValidators.isValidISessionValidator({
            hash: hash,
            account: account,
            permissionId: permissionId,
            signature: decompressedSignature
        });
    }

    /// @notice Validates an ERC-1271 signature with additional ERC-7739 content checks
    /// @dev This function performs several checks to validate the signature:
    ///      1. Verifies that the permissionId is enabled for the sender
    ///      2. Ensures the ERC-7739 content is enabled for the given permissionId
    ///      3. Checks the ERC-1271 policy
    ///      4. Validates the signature using ISessionValidator
    /// @dev This function returns false if a permissionId supplied within the signature is not
    /// enabled
    /// @dev This function returns false if the ERC-7739 content is not enabled for the given
    /// permissionId
    /// @param sender The address initiating the signature validation
    /// @param hash The hash of the data to be signed
    /// @param signature The signature to be validated (first 32 bytes contain the permissionId)
    /// @param contents The ERC-7739 content to be validated
    /// @return valid Boolean indicating whether the signature is valid
    function _erc1271IsValidSignatureNowCalldata(
        address sender,
        bytes32 hash,
        bytes calldata signature,
        bytes32 appDomainSeparator,
        bytes calldata contents,
        address sponsor,
        bytes12 lockTag
    )
        internal
        view
        virtual
        override
        returns (bool)
    {
        bytes32 contentHash = string(contents).hashERC7739Content();
        // isolate the PermissionId and actual signature from the supplied signature param
        PermissionId permissionId = PermissionId.wrap(bytes32(signature[0:32]));
        signature = signature[32:];

        // TODO: This is ass placeholder

        // make sure permissionId is enabled for sender, sponsor, and lockTag
        require(
            $smartSessionConfig[sender][lockTag].contains(
                sponsor, PermissionId.unwrap(permissionId)
            ),
            InvalidSession(permissionId)
        );

        // forgefmt: disable-next-item
        if (
            // return false if the permissionId is not enabled
            !$enabledSessions.contains(sponsor, PermissionId.unwrap(permissionId))
            // return false if the content is not enabled
            || !$enabledERC7739.enabledContentNames[permissionId][appDomainSeparator].contains(sponsor, contentHash)
        ) return false;

        // check the ERC-1271 policy
        bool valid = $erc1271Policies.checkERC1271({
            account: sponsor,
            requestSender: sender,
            hash: hash,
            signature: signature,
            permissionId: permissionId,
            configId: permissionId.toErc1271PolicyId().toConfigId(),
            minPoliciesToEnforce: 1
        });

        // if the erc1271 policy check failed, return false
        if (!valid) return valid;
        // this call reverts if the ISessionValidator is not set
        return $sessionValidators.isValidISessionValidator({
            hash: hash,
            account: sponsor,
            permissionId: permissionId,
            signature: signature
        });
    }

    /*//////////////////////////////////////////////////////////////
                                VIRTUAL
    //////////////////////////////////////////////////////////////*/

    /// @notice Returns the typed data hash for a given hash
    function _getTypedDataHashSansChainId(bytes32 hash) internal view virtual returns (bytes32);
}
