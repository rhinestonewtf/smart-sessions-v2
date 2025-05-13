// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Contracts
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

// Interfaces
import { ISmartSessionEmissary } from "@interfaces/ISmartSessionEmissary.sol";

// Libraries
import { EnumerableSet } from "@erc7579/enumerablemap4337/EnumerableSet4337.sol";

// Types
import { PermissionId } from "@smartsessions/DataTypes.sol";

contract SmartSessionEmissary is Ownable, ISmartSessionEmissary {
    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Mapping of user address => set of enabled PermissionIds
    EnumerableSet.Bytes32Set internal $enabledSessions;
    /// @notice Mapping of whitelisted sources
    mapping(address source => bool isWhitelisted) internal $whitelistedSources;

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address _owner) Ownable(_owner) {
        // Initialize the contract
    }

    /*//////////////////////////////////////////////////////////////
                               MODIFIERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Only allow calls from whitelisted sources
    modifier onlyWhitelistedSource() {
        // Check if the sender is a whitelisted source
        if (!$whitelistedSources[msg.sender]) {
            revert InvalidSignature();
        }
        _;
    }

    /*//////////////////////////////////////////////////////////////
                                 VERIFY
    //////////////////////////////////////////////////////////////*/

    function verifyExecution(
        address account,
        bytes32 hash,
        bytes calldata emissaryData,
        bytes calldata executions
    )
        external
        onlyWhitelistedSource
    {
        // Init validSig
        bool validSig;

        // unpacking data packed in emissaryData
        (SmartSessionMode mode, PermissionId permissionId, bytes calldata packedSig) =
            emissaryData.unpackMode();

        // If the SmartSession.USE mode was selected, no further policies have to be enabled.
        // We can go straight to userOp validation
        // This condition is the average case, so should be handled as the first condition
        if (mode.isUseMode()) {
            // USE mode: Directly enforce policies without enabling new ones
            validSig = _enforcePolicies({
                permissionId: permissionId,
                userOpHash: userOpHash,
                userOp: userOp,
                decompressedSignature: packedSig,
                account: account
            });
        }
        // If the SmartSession.ENABLE mode was selected, the emissaryData will contain the
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
                userOpHash: userOpHash,
                userOp: userOp,
                decompressedSignature: usePermissionSig,
                account: account
            });
        }
        // if an Unknown mode is provided, the function will revert
        else {
            revert UnsupportedSmartSessionMode(mode);
        }

        // Return the function selector on success, or a specific failure code otherwise.
        return validSIg ? this.verifyExecution.selector : bytes4(0xFFFFFFFF);
    }

    /*//////////////////////////////////////////////////////////////
                                ENFORCE
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Enforces policies and checks ISessionValidator signature for a session
     * @dev This function is the core of policy enforcement in SmartSession
     * @param permissionId The unique identifier for the permission set
     * @param hash Message hash to be validated
     * @param callData Execution data for the call
     * @param decompressedSignature The decompressed signature for validation
     * @param account The account for which policies are being enforced
     * @return vd ValidationData containing the result of policy checks
     */
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
                vd = vd.intersect(
                    $actionPolicies.actionPolicies.checkBatch7579Exec({
                        userOp: userOp,
                        permissionId: permissionId,
                        minPolicies: 1 // minimum of one actionPolicy must be set.
                     })
                );
            }
            // DEFAULT EXEC & SINGLE CALL
            else if (callType == CALLTYPE_SINGLE) {
                (address target, uint256 value, bytes calldata callData) =
                    callData.decodeUserOpCallData().decodeSingle();
                vd = vd.intersect(
                    $actionPolicies.actionPolicies.checkSingle7579Exec({
                        permissionId: permissionId,
                        target: target,
                        value: value,
                        callData: callData,
                        minPolicies: 1 // minimum of one actionPolicy must be set.
                     })
                );
            }
            // DelegateCalls are not supported by SmartSessionEmissary
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
}
