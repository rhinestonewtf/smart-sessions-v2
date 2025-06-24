// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Contracts
import { SmartSessionManager } from "@core/SmartSessionManager.sol";
import { SmartSessionERC7739 } from "@core/SmartSessionERC7739.sol";

// Interfaces
import { IERC7579Account } from "erc7579/interfaces/IERC7579Account.sol";
import { IERC1271, EIP1271_MAGIC_VALUE } from "@modulekit/module-bases/interfaces/IERC1271.sol";

// Libraries
import { EncodeLib } from "@smartsessions/lib/EncodeLib.sol";
import { SmartSessionModeLib } from "@smartsessions/lib/SmartSessionModeLib.sol";
import { IdLib } from "@smartsessions/lib/IdLib.sol";
import { IdLibV2 } from "@lib/IdLibV2.sol";
import { EnumerableSet } from "@smartsessions/utils/EnumerableSet4337.sol";
import { ExecutionLib } from "@smartsessions/lib/ExecutionLib.sol";
import { PolicyLibV2 } from "@lib/PolicyLibV2.sol";
import { PolicyLib } from "@smartsessions/lib/PolicyLib.sol";
import { SignerLib } from "@smartsessions/lib/SignerLib.sol";
import { ConfigLibV2 } from "@lib/ConfigLibV2.sol";
import { IdLib as CompactIdLib } from "@the-compact/lib/IdLib.sol";
import { HashLib } from "@smartsessions/lib/HashLib.sol";
import { HashLibV2 } from "@lib/HashLibV2.sol";
import { SignatureCheckerLib } from "@solady/utils/SignatureCheckerLib.sol";
import { SignatureLib } from "@lib/SignatureLib.sol";

// Types
import {
    PermissionId,
    SmartSessionMode,
    PolicyType,
    Session,
    ConfigId
} from "@smartsessions/DataTypes.sol";
import {
    SmartSessionEmissaryConfig,
    SmartSessionEmissaryEnable,
    SmartSessionEmissaryDisable
} from "@interfaces/ISmartSessionEmissary.sol";
import {
    ExecType,
    CallType,
    CALLTYPE_BATCH,
    CALLTYPE_SINGLE,
    EXECTYPE_DEFAULT
} from "erc7579/lib/ModeLib.sol";
import { EnableSession, DisableSession, INVALID_RETURN } from "@types/DataTypes.sol";

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
    using IdLibV2 for *;
    using EnumerableSet for *;
    using ExecutionLib for *;
    using PolicyLib for *;
    using PolicyLibV2 for *;
    using SignerLib for *;
    using HashLib for *;
    using HashLibV2 for *;
    using ConfigLibV2 for *;
    using CompactIdLib for *;
    using SignatureCheckerLib for *;
    using SignatureLib for *;

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
        SmartSessionEmissaryEnable calldata enableData
    )
        public
    {
        // Derive lockTag from allocator, scope, resetPeriod
        bytes12 lockTag =
            config.allocator.toAllocatorId().toLockTag(config.scope, config.resetPeriod);

        // Verify data expires after current block timestamp
        require(enableData.expires > block.timestamp, InvalidEmissaryEnableData());

        // Enable policies
        _enablePolicies(
            account,
            enableData.session,
            config.permissionId,
            config.arbiter,
            lockTag,
            enableData.expires,
            config.allocator,
            enableData.allocatorSig,
            enableData.userSig
        );

        // Emit event if the session is enabled
        emit SmartSessionEmissaryConfigUpdated(account, config.permissionId, lockTag);
    }

    /// @notice Removes a Smart Session Emissary configuration for a specific account
    /// @param account The address of the account for which the configuration is being removed
    /// @param config The Smart Session Emissary configuration to be removed
    /// @param disableData The disable data containing the allocatorSignature, user signature,
    ///                    disable session data, and expiration time
    function removeConfig(
        address account,
        SmartSessionEmissaryConfig calldata config,
        SmartSessionEmissaryDisable calldata disableData
    )
        external
    {
        // Derive lockTag from allocator, scope, resetPeriod
        bytes12 lockTag =
            config.allocator.toAllocatorId().toLockTag(config.scope, config.resetPeriod);

        // Verify data expires after current block timestamp
        require(disableData.expires > block.timestamp, InvalidEmissaryDisableData());

        // Disable policies
        _disablePolicies(
            account,
            disableData.session,
            config.permissionId,
            config.arbiter,
            lockTag,
            disableData.expires,
            config.allocator,
            disableData.allocatorSig,
            disableData.userSig
        );

        // Emit event if the session is removed
        emit SmartSessionEmissaryConfigUpdated(account, config.permissionId, lockTag);
    }

    /// @notice Enables policies for an account, using the provided enable data after verifying
    ///         required signatures.
    /// @param account The address of the account for which policies are being enabled
    /// @param enableData The data containing session and policy information to be enabled
    /// @param permissionId The unique identifier for the permission set
    /// @param arbiter The address of the arbiter for the session
    /// @param lockTag The lock tag associated with the session
    /// @param allocator The address of the allocator for the session
    /// @param allocatorSig The signature from the allocator authorizing the session
    function _enablePolicies(
        address account,
        EnableSession memory enableData,
        PermissionId permissionId,
        address arbiter,
        bytes12 lockTag,
        uint256 expires,
        address allocator,
        bytes calldata allocatorSig,
        bytes calldata userSig
    )
        internal
    {
        // Increment nonce to prevent replay attacks
        uint256 nonce = $emissaryNonce[account][lockTag]++;
        bytes32 hash =
            enableData.getAndVerifyDigest(account, nonce, expires, lockTag, arbiter, allocator);

        // Verify the user and allocator signatures
        hash.verifySignatures(account, allocator, allocatorSig, userSig);

        // Enable ERC1271 policies
        $enabledERC7739.enable({
            contexts: enableData.sessionToEnable.erc7739Policies.allowedERC7739Content,
            permissionId: permissionId,
            account: account
        });

        // Enable ERC1271 policies
        $erc1271Policies.enable({
            policyType: PolicyType.ERC1271,
            permissionId: permissionId,
            configId: permissionId.toErc1271PolicyId().toConfigId(),
            policyDatas: enableData.sessionToEnable.erc7739Policies.erc1271Policies,
            useRegistry: false,
            account: account
        });

        // Enable action policies
        $actionPolicies.enable({
            permissionId: permissionId,
            actionPolicyDatas: enableData.sessionToEnable.actions,
            useRegistry: false,
            account: account
        });

        // Enable mode can involve enabling ISessionValidator (new Permission)
        // or just adding policies (existing permission)
        // a) ISessionValidator is not set => enable ISessionValidator
        // b) ISessionValidator is set => just add policies (above)
        // Attention: if the same policy that has already been configured is added again,
        // the policy will be overwritten with the new configuration
        if (!_isISessionValidatorSet(permissionId, account)) {
            $sessionValidators.enable({
                permissionId: permissionId,
                sessionValidator: enableData.sessionToEnable.sessionValidator,
                sessionValidatorConfig: enableData.sessionToEnable.sessionValidatorInitData,
                useRegistry: false,
                account: account
            });
        }

        // Mark the session as enabled
        $smartSessionConfig[arbiter][lockTag].add({
            account: account,
            value: PermissionId.unwrap(permissionId)
        });
    }

    /// @notice Disables policies for an account, using the provided disable data after verifying
    ///         required signatures.
    /// @param account The address of the account for which policies are being disabled
    /// @param disableData The data containing session and policy information to be disabled
    /// @param permissionId The unique identifier for the permission set
    /// @param arbiter The address of the arbiter for the session
    /// @param lockTag The lock tag associated with the session
    /// @param allocator The address of the allocator for the session
    /// @param allocatorSig The signature from the allocator authorizing the session
    /// @param userSig The signature from the user authorizing the session disable
    function _disablePolicies(
        address account,
        DisableSession memory disableData,
        PermissionId permissionId,
        address arbiter,
        bytes12 lockTag,
        uint256 expires,
        address allocator,
        bytes calldata allocatorSig,
        bytes calldata userSig
    )
        internal
    {
        // Increment nonce to prevent replay attacks
        uint256 nonce = $emissaryNonce[account][lockTag]++;
        /*//////////////////////////////////////////////////////////////
                                  TODO
        //////////////////////////////////////////////////////////////*/

        // bytes32 hash =
        //     disableData.getAndVerifyDigest(account, nonce, expires, lockTag, arbiter, allocator);
    }

    /*//////////////////////////////////////////////////////////////
                                 CLAIM
    //////////////////////////////////////////////////////////////*/

    /// @notice Verifies digests using SmartSession (mode 2)
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
    /// @param lockTag The lock tag associated with the execution configuration
    /// @return bytes4 The function selector on success, or a specific failure code otherwise
    function _verifyExecutionSmartSession(
        address account,
        bytes32 hash,
        bytes calldata emissaryData,
        bytes calldata executions,
        bytes12 lockTag
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
                account: account,
                lockTag: lockTag
            });
        }
        // if an Unknown mode is provided, the function will revert
        else {
            revert UnsupportedSmartSessionMode(mode);
        }

        // Return the function selector on success, or a specific failure code otherwise.
        return validSig ? this.verifyExecution.selector : INVALID_RETURN;
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
    /// @param lockTag The lock tag associated with the session
    /// @return validSig True if the signature is valid, false otherwise
    function _enforcePolicies(
        PermissionId permissionId,
        bytes32 hash,
        bytes calldata callData,
        bytes memory decompressedSignature,
        address account,
        bytes12 lockTag
    )
        internal
        returns (bool validSig)
    {
        // ensure that the permissionId is enabled
        if (
            !$smartSessionConfig[msg.sender][lockTag].contains(
                account, PermissionId.unwrap(permissionId)
            )
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

        // forgefmt: disable-next-item
        if (
            // return false if permissionId is not enabled for lockTag and sender
             !$smartSessionConfig[sender][lockTag].contains(
                sponsor, PermissionId.unwrap(permissionId)
            ) || 
            // return false if the content is not enabled
             !$enabledERC7739.enabledContentNames[permissionId][appDomainSeparator].contains(sponsor, contentHash)
        ) return false;

        // check the ERC-1271 policy
        bool valid = $erc1271Policies.checkERC1271({
            account: sponsor,
            requestSender: sender,
            hash: hash,
            signature: signature,
            permissionId: permissionId,
            configId: permissionId.toErc1271PolicyId().toConfigId(sponsor),
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
