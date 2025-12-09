// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Contracts
import { SudoPolicy } from "@smartsessions/external/policies/SudoPolicy.sol";
import { YesSessionValidator } from "@smartsessions-test/mock/YesSessionValidator.sol";
import { NoSessionValidator } from "@test/mock/NoSessionValidator.sol";
import { NoValidator } from "@test/mock/NoValidator.sol";
import { NoPolicy } from "@smartsessions-test/mock/NoPolicy.sol";
import { EIP712 } from "@solady/utils/EIP712.sol";
import {
    SmartSessionCompatibilityFallback
} from "@smartsessions/SmartSessionCompatibilityFallback.sol";

// Interfaces
import { IERC7579Account } from "erc7579/interfaces/IERC7579Account.sol";

// Libraries
import { ModuleKitHelpers } from "@modulekit/ModuleKit.sol";

// Dependencies
import { Test } from "@forge-std/Test.sol";
import { RhinestoneModuleKit } from "@modulekit/ModuleKit.sol";
import { Vm } from "@forge-std/Vm.sol";
import { ECDSA } from "solady/utils/ECDSA.sol";
import { Solarray } from "solarray/Solarray.sol";

// Types
import { AccountInstance } from "@modulekit/ModuleKit.sol";
import { PolicyData, EIP712Domain } from "@smartsessions/DataTypes.sol";
import { Execution, ExecutionLib } from "@smartsessions/lib/ExecutionLib.sol";
import {
    ExecType,
    CallType,
    CALLTYPE_BATCH,
    CALLTYPE_SINGLE,
    EXECTYPE_DEFAULT,
    CALLTYPE_STATIC,
    ModeCode,
    ModeLib
} from "erc7579/lib/ModeLib.sol";
import { MODULE_TYPE_FALLBACK } from "erc7579/interfaces/IERC7579Module.sol";
import { PolicyConfig, BaseConfigLib } from "@policies/claim/base/lib/BaseConfigLib.sol";

/// @notice An abstract base test contract that provides common test logic.
abstract contract Base_Test is Test, RhinestoneModuleKit {
    /*//////////////////////////////////////////////////////////////
                                LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using ModuleKitHelpers for *;
    using BaseConfigLib for uint32;

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    bytes32 constant EIP712_DOMAIN_TYPEHASH =
        0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f;

    /*//////////////////////////////////////////////////////////////
                               VARIABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice A wallet that represents an admin address.
    Vm.Wallet internal admin;

    /// @notice Address of the target contract.
    address internal target;

    /// @notice Default value to be used in tests.
    uint256 internal value;

    // A smart account instance
    AccountInstance internal instance;

    // The SudoPolicy contract instance.
    SudoPolicy internal sudoPolicy;

    // The default session validator contract instance.
    YesSessionValidator internal yesSessionValidator;

    // The default invalid session validator contract instance.
    NoSessionValidator internal noSessionValidator;

    // The default invalid validator contract instance.
    NoValidator internal noValidator;

    // The default invalid policy contract instance.
    NoPolicy internal noPolicy;

    // The fallback module instance.
    SmartSessionCompatibilityFallback internal fallbackModule;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual {
        // Create the admin address.
        admin = vm.createWallet("admin");
        // Initialize the module kit.
        super.init();
        // Set the target address.
        target = makeAddr("target");
        // Set the default value.
        value = 1 ether;
        // Deploy account
        instance = makeAccountInstance("DefaultAccount");
        // Deploy the SudoPolicy contract.
        sudoPolicy = new SudoPolicy();
        // Deploy the YesSessionValidator contract.
        yesSessionValidator = new YesSessionValidator();
        // Deploy the NoSessionValidator contract.
        noSessionValidator = new NoSessionValidator();
        // Deploy the NoValidator contract.
        noValidator = new NoValidator();
        // Deploy the NoPolicy contract.
        noPolicy = new NoPolicy();
        // Deploy fallback module
        fallbackModule = new SmartSessionCompatibilityFallback();
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Sign a message with the admin's private key.
    /// @param _hash The hash of the message to sign.
    /// @return signature The signature of the message.
    function adminSign(bytes32 _hash) internal returns (bytes memory signature) {
        // Sign the message with the admin's private key.
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(admin, ECDSA.toEthSignedMessageHash(_hash));
        // Return the signature.
        return abi.encodePacked(r, s, v);
    }

    function getCallData(
        Execution[] calldata executions,
        bytes calldata context
    )
        external
        pure
        returns (bytes memory callData)
    {
        if (executions.length == 0) {
            revert("No executions provided");
        }
        ModeCode mode = ModeCode.wrap(bytes32(context[24:56]));
        CallType callType;
        assembly {
            callType := mode
        }
        if (callType == CALLTYPE_SINGLE) {
            callData = abi.encodeCall(
                IERC7579Account.execute,
                (
                    mode,
                    ExecutionLib.encodeSingle(
                        executions[0].target, executions[0].value, executions[0].callData
                    )
                )
            );
        } else if (callType == CALLTYPE_BATCH) {
            callData = abi.encodeCall(
                IERC7579Account.execute, (mode, ExecutionLib.encodeBatch(executions))
            );
        }
    }

    /// @notice Builds a PolicyConfig with specified field mode
    function _buildConfig(uint8 fieldId, uint8 mode) internal pure returns (PolicyConfig) {
        uint32 modeConfig = uint32(0).setFieldMode(fieldId, mode);
        return PolicyConfig.wrap(modeConfig);
    }

    /// @notice Helper to create mode config with specific field mode
    function _createModeConfig(uint8 fieldId, uint8 mode) internal pure returns (uint32) {
        return uint32(mode) << (fieldId * 2);
    }
}
