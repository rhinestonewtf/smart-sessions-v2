// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

// Dependencies
import {
    SmartSessionEmissary_Integration_Base_Test
} from "@test/integration/Base.integration.t.sol";

// Interfaces
import { ISessionValidator } from "@smartsessions/interfaces/ISessionValidator.sol";

// Libraries
import { AccountInstance, ModuleKitHelpers } from "@modulekit/ModuleKit.sol";
import { SmartExecutionLib, Execution } from "@compact-utils/common/SmartExecutionLib.sol";
import { EMISSARY_SMART_SESSION } from "@lib/ModeLib.sol";

// Types
import {
    PermissionId,
    PolicyData,
    ActionData,
    ERC7739Data,
    ERC7739Context,
    SmartSessionMode
} from "@smartsessions/DataTypes.sol";
import { Session } from "@types/DataTypes.sol";
import { Types } from "@rhinestone/compact-utils/src/types/OrderTypes.sol";
import { Vm } from "forge-std/Vm.sol";

/// @title Action Policy Integration Test Base
/// @author Rhinestone
/// @notice Abstract base contract for testing action policies with SmartSessionEmissary
abstract contract ActionPolicy_Integration_Test is SmartSessionEmissary_Integration_Base_Test {
    using ModuleKitHelpers for *;
    using SmartExecutionLib for *;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        super.setUp();
    }

    /*//////////////////////////////////////////////////////////////
                     ACTION SESSION SETUP
    //////////////////////////////////////////////////////////////*/

    /// @notice Enables a session with action policies for a specific target/selector
    /// @param account The account to enable the session on
    /// @param policy The policy contract address
    /// @param policyInitData Policy initialization data
    /// @param signer The address that will sign for this session
    /// @param target The target contract
    /// @param selector The function selector
    /// @return permissionId The unique identifier for this enabled session
    function enableActionSession(
        AccountInstance memory account,
        address policy,
        bytes memory policyInitData,
        address signer,
        address target,
        bytes4 selector
    )
        internal
        returns (PermissionId)
    {
        PolicyData[] memory policies = new PolicyData[](1);
        policies[0] = PolicyData({ policy: policy, initData: policyInitData });

        return enableActionSessionWithPolicies(account, policies, signer, target, selector);
    }

    /// @notice Enables an action session using the default test wallet
    function enableActionSession(
        AccountInstance memory account,
        address policy,
        bytes memory policyInitData,
        address target,
        bytes4 selector
    )
        internal
        returns (PermissionId)
    {
        return
            enableActionSession(account, policy, policyInitData, testWallet.addr, target, selector);
    }

    /// @notice Enables a session with multiple action policies
    function enableActionSessionWithPolicies(
        AccountInstance memory account,
        PolicyData[] memory actionPolicies,
        address signer,
        address target,
        bytes4 selector
    )
        internal
        returns (PermissionId)
    {
        ActionData[] memory actions = new ActionData[](1);
        actions[0] = ActionData({
            actionTarget: target, actionTargetSelector: selector, actionPolicies: actionPolicies
        });

        Session memory session = Session({
            sessionValidator: ISessionValidator(address(ownableValidator)),
            salt: keccak256(abi.encodePacked("actionSession", block.timestamp)),
            sessionValidatorInitData: createValidatorInitData(signer),
            erc7739Policies: ERC7739Data({
                allowedERC7739Content: new ERC7739Context[](0), erc1271Policies: new PolicyData[](0)
            }),
            actions: actions,
            claimPolicies: new PolicyData[](0)
        });

        return enableSession(account, session);
    }

    /// @notice Enables a session with multiple actions
    function enableActionSessionMultipleActions(
        AccountInstance memory account,
        ActionData[] memory actions,
        address signer
    )
        internal
        returns (PermissionId)
    {
        Session memory session = Session({
            sessionValidator: ISessionValidator(address(ownableValidator)),
            salt: keccak256(abi.encodePacked("multiActionSession", block.timestamp)),
            sessionValidatorInitData: createValidatorInitData(signer),
            erc7739Policies: ERC7739Data({
                allowedERC7739Content: new ERC7739Context[](0), erc1271Policies: new PolicyData[](0)
            }),
            actions: actions,
            claimPolicies: new PolicyData[](0)
        });

        return enableSession(account, session);
    }

    /// @notice Enables a session with multiple actions using default wallet
    function enableActionSessionMultipleActions(
        AccountInstance memory account,
        ActionData[] memory actions
    )
        internal
        returns (PermissionId)
    {
        return enableActionSessionMultipleActions(account, actions, testWallet.addr);
    }

    /*//////////////////////////////////////////////////////////////
                     EXECUTION VALIDATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Validates an execution using the default test wallet
    /// @param account The account for policy enforcement
    /// @param permissionId The session permission to use
    /// @param digest The digest to validate (typically from intent system)
    /// @param target The target contract
    /// @param value The ETH value to send
    /// @param callData The calldata to execute
    /// @return valid True if execution passes all policy checks
    function validateExecution(
        AccountInstance memory account,
        PermissionId permissionId,
        bytes32 digest,
        address target,
        uint256 value,
        bytes memory callData
    )
        internal
        returns (bool valid)
    {
        return validateExecutionWithKey(
            account, permissionId, digest, target, value, callData, testWallet.privateKey
        );
    }

    /// @notice Validates an execution with specific private key
    function validateExecutionWithKey(
        AccountInstance memory account,
        PermissionId permissionId,
        bytes32 digest,
        address target,
        uint256 value,
        bytes memory callData,
        uint256 privateKey
    )
        internal
        returns (bool valid)
    {
        // Build single execution
        Execution[] memory executions = new Execution[](1);
        executions[0] = Execution({ target: target, value: value, callData: callData });

        // Encode as operation using SmartExecutionLib
        Types.Operation memory operation = SmartExecutionLib.SigMode.EMISSARY.encode(executions);

        return validateExecutionWithOperationAndKey(
            account, permissionId, digest, operation, privateKey
        );
    }

    /// @notice Validates an execution with a pre-built operation
    function validateExecutionWithOperation(
        AccountInstance memory account,
        PermissionId permissionId,
        bytes32 digest,
        Types.Operation memory operation
    )
        internal
        returns (bool valid)
    {
        return validateExecutionWithOperationAndKey(
            account, permissionId, digest, operation, testWallet.privateKey
        );
    }

    /// @notice Validates an execution with a pre-built operation and specific key
    function validateExecutionWithOperationAndKey(
        AccountInstance memory account,
        PermissionId permissionId,
        bytes32 digest,
        Types.Operation memory operation,
        uint256 privateKey
    )
        internal
        returns (bool valid)
    {
        // Sign the digest
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Build emissary data: [mode (1)][permissionId (32)] [signature]
        bytes memory emissaryData = abi.encodePacked(SmartSessionMode.USE, permissionId, signature);

        // Call verifyExecution
        vm.prank(MOCK_INTENT_EXECUTOR);
        try smartSessionEmissary.verifyExecution(
            account.account, digest, emissaryData, operation
        ) returns (
            bytes4 result
        ) {
            return result == smartSessionEmissary.verifyExecution.selector;
        } catch {
            return false;
        }
    }

    /// @notice Validates a batch of executions using default wallet
    function validateBatchExecution(
        AccountInstance memory account,
        PermissionId permissionId,
        bytes32 digest,
        Execution[] memory executions
    )
        internal
        returns (bool valid)
    {
        return validateBatchExecutionWithKey(
            account, permissionId, digest, executions, testWallet.privateKey
        );
    }

    /// @notice Validates a batch of executions with specific private key
    function validateBatchExecutionWithKey(
        AccountInstance memory account,
        PermissionId permissionId,
        bytes32 digest,
        Execution[] memory executions,
        uint256 privateKey
    )
        internal
        returns (bool valid)
    {
        // Encode as operation using SmartExecutionLib
        Types.Operation memory operation = SmartExecutionLib.SigMode.EMISSARY.encode(executions);

        return validateExecutionWithOperationAndKey(
            account, permissionId, digest, operation, privateKey
        );
    }

    /// @notice Validates a batch of executions with arrays (convenience function)
    function validateBatchExecution(
        AccountInstance memory account,
        PermissionId permissionId,
        bytes32 digest,
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory callDatas
    )
        internal
        returns (bool valid)
    {
        require(
            targets.length == values.length && values.length == callDatas.length,
            "Array length mismatch"
        );

        Execution[] memory executions = new Execution[](targets.length);
        for (uint256 i = 0; i < targets.length; i++) {
            executions[i] =
                Execution({ target: targets[i], value: values[i], callData: callDatas[i] });
        }

        return validateBatchExecution(account, permissionId, digest, executions);
    }

    /*//////////////////////////////////////////////////////////////
                         OPERATION BUILDERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Builds a single execution operation
    function buildOperation(
        address target,
        uint256 value,
        bytes memory callData
    )
        internal
        pure
        returns (Types.Operation memory)
    {
        Execution[] memory executions = new Execution[](1);
        executions[0] = Execution({ target: target, value: value, callData: callData });
        return SmartExecutionLib.SigMode.EMISSARY.encode(executions);
    }

    /// @notice Builds a batch execution operation
    function buildBatchOperation(Execution[] memory executions)
        internal
        pure
        returns (Types.Operation memory)
    {
        return SmartExecutionLib.SigMode.EMISSARY.encode(executions);
    }

    /*//////////////////////////////////////////////////////////////
                              HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Creates a simple digest for testing
    /// @dev In production, this comes from the intent/compact system
    function createTestDigest(
        address account,
        address target,
        uint256 value,
        bytes memory callData,
        uint256 nonce
    )
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(account, target, value, callData, nonce));
    }

    /// @notice Creates a batch test digest
    function createBatchTestDigest(
        address account,
        Execution[] memory executions,
        uint256 nonce
    )
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(account, executions, nonce));
    }

    /// @notice Helper to create an ActionData struct
    function createActionData(
        address target,
        bytes4 selector,
        address policy,
        bytes memory policyInitData
    )
        internal
        pure
        returns (ActionData memory)
    {
        PolicyData[] memory policies = new PolicyData[](1);
        policies[0] = PolicyData({ policy: policy, initData: policyInitData });

        return ActionData({
            actionTarget: target, actionTargetSelector: selector, actionPolicies: policies
        });
    }

    /// @notice Helper to create an Execution struct
    function createExecution(
        address target,
        uint256 value,
        bytes4 selector
    )
        internal
        pure
        returns (Execution memory)
    {
        return
            Execution({ target: target, value: value, callData: abi.encodeWithSelector(selector) });
    }

    /// @notice Helper to create an Execution struct with calldata
    function createExecution(
        address target,
        uint256 value,
        bytes memory callData
    )
        internal
        pure
        returns (Execution memory)
    {
        return Execution({ target: target, value: value, callData: callData });
    }
}
