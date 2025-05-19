// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Contracts
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { SmartSessionManager } from "@core/SmartSessionManager.sol";

// Interfaces
import { ISmartSessionExecutionVerifier } from "@interfaces/ISmartSessionExecutionVerifier.sol";
import { IERC1271, EIP1271_MAGIC_VALUE } from "@modulekit/module-bases/interfaces/IERC1271.sol";
import { IERC7579Account } from "erc7579/interfaces/IERC7579Account.sol";

// Libraries
import { EncodeLib } from "@smartsessions/lib/EncodeLib.sol";
import { SmartSessionModeLib } from "@smartsessions/lib/SmartSessionModeLib.sol";
import { IdLib } from "@smartsessions/lib/IdLib.sol";
import { EnumerableSet } from "@smartsessions/utils/EnumerableSet4337.sol";
import { ExecutionLib } from "@smartsessions/lib/ExecutionLib.sol";
import { PolicyLib } from "@smartsessions/lib/PolicyLib.sol";
import { PolicyLibV2 } from "@lib/PolicyLibV2.sol";
import { SignerLib } from "@smartsessions/lib/SignerLib.sol";
import { HashLib } from "@smartsessions/lib/HashLib.sol";
import { ConfigLib } from "@smartsessions/lib/ConfigLib.sol";

// Types
import {
    PermissionId, SmartSessionMode, EnableSession, Session
} from "@smartsessions/DataTypes.sol";
import {
    ExecType,
    CallType,
    CALLTYPE_BATCH,
    CALLTYPE_SINGLE,
    EXECTYPE_DEFAULT
} from "erc7579/lib/ModeLib.sol";

// TODO: Name is kind of wack
contract SmartSessionExecutionVerifier is SmartSessionManager {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using EncodeLib for *;
    using SmartSessionModeLib for *;
    using IdLib for *;
    using EnumerableSet for *;
    using ExecutionLib for *;
    using PolicyLibV2 for *;
    using PolicyLib for *;
    using SignerLib for *;
    using HashLib for *;
    using ConfigLib for *;

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address _owner) Ownable(_owner) { }

    /*//////////////////////////////////////////////////////////////
                                 VERIFY
    //////////////////////////////////////////////////////////////*/

    /// @notice Validates executions for an account using it's enabled policies
    /// @dev This function is called by a whitelisted source, which is assumed to verify that
    ///      executions are included in the hash that is passed to this function and signed by the
    ///      session key
    /// @param account The account for which the policies are being enforced
    /// @param hash The hash of the user operation
    /// @param data Packed smart session data including mode, permissionId and signature
    /// @param executions The execution data for the user operation
    /// @return bytes4 The function selector on success, or a specific failure code otherwise
    function verifyExecution(
        address account,
        bytes32 hash,
        bytes calldata data,
        bytes calldata executions
    )
        external
        onlyWhitelistedSource
        returns (bytes4)
    {
        // Init validSig
        bool validSig;

        // unpacking data packed in data
        (SmartSessionMode mode, PermissionId permissionId, bytes calldata packedSig) =
            data.unpackMode();

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
        // If the SmartSession.ENABLE mode was selected, the data will contain the
        // EnableSession data
        // This data will be used to enable policies and signer for the session
        // The signature of the user on the EnableSession data will be checked
        // If the signature is valid, the policies and signer will be enabled
        // after enabling the session, the policies will be enforced on the userOp similarly to the
        // SmartSession.USE
        else if (mode.isEnableMode()) {
            // unpack the EnableSession data and signature
            // calculate the permissionId from the Session data
            EnableSession memory enableData;
            bytes memory usePermissionSig;
            (enableData, usePermissionSig) = packedSig.decodeEnable();
            permissionId = enableData.sessionToEnable.toPermissionIdMemory();

            // ENABLE mode: Enable new policies and then enforce them
            _enablePolicies({
                enableData: enableData,
                permissionId: permissionId,
                account: account,
                mode: mode
            });

            validSig = _enforcePolicies({
                permissionId: permissionId,
                hash: hash,
                callData: executions,
                decompressedSignature: usePermissionSig,
                account: account
            });
        }
        // if an Unknown mode is provided, the function will revert
        else {
            revert UnsupportedSmartSessionMode(mode);
        }

        // Return the function selector on success, or a specific failure code otherwise.
        return validSig ? this.verifyExecution.selector : bytes4(0xFFFFFFFF);
    }

    /*//////////////////////////////////////////////////////////////
                                ENFORCE
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

    /*//////////////////////////////////////////////////////////////
                                ENABLE
    //////////////////////////////////////////////////////////////*/

    /// @notice Enables policies for a session during user operation validation
    /// @dev This function handles the enabling of new policies and session validators
    /// @param enableData The EnableSession data containing the session to enable
    /// @param permissionId The unique identifier for the permission set
    /// @param account The account for which policies are being enabled
    /// @param mode The SmartSession mode being used
    function _enablePolicies(
        EnableSession memory enableData,
        PermissionId permissionId,
        address account,
        SmartSessionMode mode
    )
        internal
    {
        // Increment nonce to prevent replay attacks
        uint256 nonce = $signerNonce[permissionId][account]++;
        bytes32 hash = enableData.getAndVerifyDigest(account, nonce, mode);

        // require signature on account
        // this is critical as it is the only way to ensure that the user is aware of the policies
        // and signer
        // NOTE: although SmartSession implements a ERC1271 feature,
        // it CAN NOT be used as a valid ERC1271 validator for
        // this step. SmartSessions ERC1271 function must prevent this
        if (
            IERC1271(account).isValidSignature(hash, enableData.permissionEnableSig)
                != EIP1271_MAGIC_VALUE
        ) {
            revert InvalidEnableSignature(account, hash);
        }

        // Determine if registry should be used based on the mode
        bool useRegistry = mode.useRegistry();

        // Enable action policies
        $actionPolicies.enable({
            permissionId: permissionId,
            actionPolicyDatas: enableData.sessionToEnable.actions,
            useRegistry: useRegistry
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
                useRegistry: useRegistry
            });
        }

        // Mark the session as enabled
        $enabledSessions.add(msg.sender, PermissionId.unwrap(permissionId));
    }
}
