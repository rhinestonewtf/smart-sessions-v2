// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import { Test } from "@forge-std/Test.sol";
import { OneTimeUseIdPolicy_Unit_Test } from "../OneTimeUseIdPolicy.t.sol";

// Contracts
import { OneTimeUseIdPolicy } from "@policies/onetime/OneTimeUseIdPolicy.sol";

// Interfaces
import { IOneTimeUseIdPolicy } from "@policies/onetime/interfaces/IOneTimeUseIdPolicy.sol";
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import { VALIDATION_FAILED } from "erc7579/interfaces/IERC7579Module.sol";

/// @title OneTimeUseIdPolicy.checkAction Unit Tests
/// @notice Unit tests for the checkAction function
contract OneTimeUseIdPolicy_checkAction_Unit_Test is OneTimeUseIdPolicy_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                 SCOPING
    //////////////////////////////////////////////////////////////*/

    /// @notice Test an unconfigured configId fails closed
    function test_checkAction_unconfigured_returnsFailed() external {
        ConfigId never = ConfigId.wrap(keccak256("never.installed"));

        assertEq(_validate(never), FAILED, "an unconfigured slot fails closed");
    }

    /*//////////////////////////////////////////////////////////////
                            SPEND STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Test an unburned id lets the batch through
    function test_checkAction_unburnedId_returnsSuccess() external {
        assertEq(_validate(cfgA), SUCCESS, "an unburned id must let the batch through");
    }

    /// @notice Test a burned id refuses every further settlement
    function test_checkAction_burnedId_returnsFailed() external {
        assertEq(_validate(cfgA), SUCCESS, "settlement one validates");

        _consumeFor(ID_A, WITNESS_1);

        assertEq(_validate(cfgA), FAILED, "settlement two must be refused");
    }

    /// @notice Test the burn is visible from every action slot pinned to the same id
    function test_checkAction_burnVisibleAcrossActionSlots() external {
        ConfigId cfgC = ConfigId.wrap(keccak256("session.A.slot.2"));
        _install(cfgC, ID_A);

        _consumeFor(ID_A, WITNESS_1);

        assertEq(_validate(cfgA), FAILED, "slot A sees the burn");
        assertEq(_validate(cfgC), FAILED, "the other slot on the same session sees the same burn");
    }

    /// @notice Test every execution in a batch validates while the id stays unburned
    function test_checkAction_validatesEveryExecutionInABatch() external {
        for (uint256 i; i < 8; ++i) {
            assertEq(
                _validate(i % 2 == 0 ? cfgA : cfgB),
                SUCCESS,
                "every execution in one settlement must validate"
            );
        }
    }

    /// @notice Test checkAction does not itself burn the id
    function test_checkAction_doesNotBurn() external {
        _validate(cfgA);

        assertFalse(policy.isConsumed(account, ID_A), "validation must not consume the id");
    }

    /*//////////////////////////////////////////////////////////////
                         THE consume SELF-CALL
    //////////////////////////////////////////////////////////////*/

    /// @notice Test a session may burn its own id via the executor route
    function test_checkAction_consumeOwnId_returnsSuccess() external {
        bytes memory burnOwn = abi.encodeCall(IOneTimeUseIdPolicy.consume, (ID_B));

        uint256 result = _checkAction(cfgB, address(policy), burnOwn);

        assertEq(result, SUCCESS, "its own id is permitted");
    }

    /// @notice Test a session may not name another session's id in a consume call
    function test_checkAction_consumeForeignId_returnsFailed() external {
        bytes memory burnSomeoneElse = abi.encodeCall(IOneTimeUseIdPolicy.consume, (ID_A));

        uint256 result = _checkAction(cfgB, address(policy), burnSomeoneElse);

        assertEq(result, FAILED, "session B may not burn session A's id");
    }

    /// @notice Test an action unrelated to this policy is unaffected by the binding
    function test_checkAction_unrelatedAction_returnsSuccess() external {
        uint256 result = _checkAction(cfgB, makeAddr("someToken"), hex"a9059cbb");

        assertEq(result, SUCCESS, "the binding only applies to self-calls");
    }

    /*//////////////////////////////////////////////////////////////
                    THE consumeFor SELF-CALL IS REFUSED
    //////////////////////////////////////////////////////////////*/

    /// @notice Test the executor route may not nominate a settlement for its own id
    function test_checkAction_consumeForOwnId_returnsFailed() external {
        bytes memory nominateOwn = abi.encodeCall(IOneTimeUseIdPolicy.consumeFor, (ID_B, WITNESS_1));

        uint256 result = _checkAction(cfgB, address(policy), nominateOwn);

        assertEq(result, FAILED, "the executor route may not nominate");
    }

    /// @notice Test the executor route may not nominate a settlement for another session's id
    function test_checkAction_consumeForForeignId_returnsFailed() external {
        bytes memory nominateOther =
            abi.encodeCall(IOneTimeUseIdPolicy.consumeFor, (ID_A, WITNESS_1));

        uint256 result = _checkAction(cfgB, address(policy), nominateOther);

        assertEq(result, FAILED, "and certainly not another session's id");
    }

    /// @notice Test a malformed consume self-call (selector-only calldata) fails closed
    function test_checkAction_malformedConsume_failsClosed() external {
        bytes memory malformed = abi.encodePacked(IOneTimeUseIdPolicy.consume.selector);

        uint256 result = _checkAction(cfgB, address(policy), malformed);

        assertEq(result, FAILED, "malformed consume calldata must fail closed");
    }
}

/// @title The cross-transaction half of checkAction's strictness
/// @notice Split into its own contract deliberately. Transient storage survives every call
///         inside one test body - a forge test body IS one transaction - but it IS cleared
///         between `setUp` and the body. Burning in `setUp` is therefore the only way to observe
///         a LATER transaction.
contract OneTimeUseIdPolicy_checkAction_CrossTransaction_Unit_Test is Test {
    OneTimeUseIdPolicy internal policy;

    address internal constant PERMIT2 = 0x000000000022D473030F116dDEE9F6B43aC78BA3;
    address internal multiplexer = makeAddr("multiplexer");
    address internal account = makeAddr("account");

    ConfigId internal cfg = ConfigId.wrap(keccak256("session.A"));
    uint256 internal constant ID = 0xBEEF;
    uint256 internal constant WITNESS = 1337;

    /// @dev The burn happens HERE, so the test body below runs in a different transaction
    function setUp() public {
        policy = new OneTimeUseIdPolicy(ISignatureTransfer(PERMIT2), makeAddr("intentExecutor"));

        vm.prank(multiplexer);
        policy.initializeWithMultiplexer(account, cfg, abi.encodePacked(bytes32(ID)));

        vm.prank(account);
        policy.consumeFor(ID, WITNESS);
    }

    /// @notice Test a burn from an earlier transaction still refuses the action surface
    function test_checkAction_crossTransactionBurnAlsoRefuses() external {
        vm.prank(multiplexer);
        assertEq(
            policy.checkAction(cfg, account, address(0), 0, ""),
            VALIDATION_FAILED,
            "the action surface does not tolerate a burn from an earlier transaction either"
        );
    }
}
