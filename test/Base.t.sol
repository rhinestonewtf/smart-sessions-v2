// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Contracts
import { SudoPolicy } from "@smartsessions/external/policies/SudoPolicy.sol";
import { YesSessionValidator } from "@smartsessions-test/mock/YesSessionValidator.sol";

// Interfaces
import { IERC7579Account } from "erc7579/interfaces/IERC7579Account.sol";

// Dependencies
import { Test } from "@forge-std/Test.sol";
import { RhinestoneModuleKit } from "@modulekit/ModuleKit.sol";
import { Vm } from "@forge-std/Vm.sol";
import { ECDSA } from "solady/utils/ECDSA.sol";
import { Solarray } from "solarray/Solarray.sol";

// Types
import { AccountInstance } from "@modulekit/ModuleKit.sol";
import { ERC7739Data, PolicyData, ERC7739Context, EIP712Domain } from "@smartsessions/DataTypes.sol";
import { Execution, ExecutionLib } from "@smartsessions/lib/ExecutionLib.sol";
import {
    ExecType,
    CallType,
    CALLTYPE_BATCH,
    CALLTYPE_SINGLE,
    EXECTYPE_DEFAULT,
    ModeCode,
    ModeLib
} from "erc7579/lib/ModeLib.sol";

/// @notice An abstract base test contract that provides common test logic.
abstract contract Base_Test is Test, RhinestoneModuleKit {
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

    /// @notice Get the empty ERC7739 data.
    function _getEmptyERC7739Data(
        string memory content,
        PolicyData[] memory erc1271Policies
    )
        internal
        pure
        returns (ERC7739Data memory)
    {
        ERC7739Context[] memory contents = new ERC7739Context[](1);
        contents[0].contentNames = Solarray.strings(content);
        contents[0].appDomainSeparator = hash(
            EIP712Domain({
                name: "Forge",
                version: "1",
                chainId: 1,
                verifyingContract: address(0x6605F8785E09a245DD558e55F9A0f4A508434503)
            })
        );
        return ERC7739Data({ allowedERC7739Content: contents, erc1271Policies: erc1271Policies });
    }

    /// @notice Hash the EIP712 domain.
    function hash(EIP712Domain memory erc7739Data) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes(erc7739Data.name)),
                keccak256(bytes(erc7739Data.version)),
                erc7739Data.chainId,
                erc7739Data.verifyingContract
            )
        );
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
}
