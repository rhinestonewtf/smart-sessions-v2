// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import { Test } from "@forge-std/Test.sol";

// Contracts
import { Permit2SenderPolicy } from "@policies/claim/permit2/Permit2SenderPolicy.sol";

// Interfaces
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";

/// @title Permit2SenderPolicy Unit Test Base
/// @notice Base contract for Permit2SenderPolicy unit tests
abstract contract Permit2SenderPolicy_Unit_Test is Test {
    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @dev The canonical Permit2 deployment address
    address internal constant PERMIT2 = 0x000000000022D473030F116dDEE9F6B43aC78BA3;

    ConfigId internal cfg = ConfigId.wrap(keccak256("session"));

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    Permit2SenderPolicy internal policy;

    address internal multiplexer;
    address internal account;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual {
        multiplexer = makeAddr("multiplexer");
        account = makeAddr("account");

        policy = new Permit2SenderPolicy(ISignatureTransfer(PERMIT2));
    }

    /*//////////////////////////////////////////////////////////////
                               HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice The ERC-1271 check for a request sent by `sender`, as the multiplexer
    function _check(address sender) internal returns (bool) {
        vm.prank(multiplexer);
        return policy.check1271SignedAction(cfg, sender, account, bytes32(0), "");
    }
}
