// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";

import { OneTimeUseIdPolicy } from "@policies/onetime/OneTimeUseIdPolicy.sol";
import { IOneTimeUseIdPolicy } from "@policies/onetime/interfaces/IOneTimeUseIdPolicy.sol";
import { I1271Policy } from "@smartsessions/interfaces/IPolicy.sol";

import { ConfigId } from "@smartsessions/DataTypes.sol";
import { VALIDATION_SUCCESS, VALIDATION_FAILED } from "erc7579/interfaces/IERC7579Module.sol";

/// @title Audit regressions
/// @notice Every test here reproduced a working exploit before the fix. They are kept as the
///         permanent record that it stays closed. The first settlement runs in `setUp` where the
///         property needs a real transaction boundary — transient storage is cleared there, and
///         nowhere inside a test body.
contract OneTimeUseIdAuditRegressions_Test is Test {
    OneTimeUseIdPolicy internal policy;

    address internal multiplexer = makeAddr("multiplexer");
    address internal account = makeAddr("account");

    ConfigId internal cfgA = ConfigId.wrap(keccak256("session.A"));
    ConfigId internal cfgB = ConfigId.wrap(keccak256("session.B"));

    uint256 internal constant ID_A = 0xBEEF;
    uint256 internal constant ID_B = 0xCAFE;

    function setUp() public {
        policy = new OneTimeUseIdPolicy();

        vm.startPrank(multiplexer);
        policy.initializeWithMultiplexer(account, cfgA, abi.encodePacked(bytes32(ID_A)));
        policy.initializeWithMultiplexer(account, cfgB, abi.encodePacked(bytes32(ID_B)));
        vm.stopPrank();

        // Session A settles legitimately, in an EARLIER transaction.
        vm.prank(account);
        policy.consume(ID_A);
    }

    function _read(ConfigId c) internal returns (bool) {
        vm.prank(multiplexer);
        return policy.check1271SignedAction(c, address(0), account, bytes32(0), "");
    }

    function _validate(ConfigId c) internal returns (uint256) {
        vm.prank(multiplexer);
        return policy.checkAction(c, account, address(0), 0, "");
    }

    /*//////////////////////////////////////////////////////////////
                    F1 — TOLERANCE SCOPED TO THE SETTLEMENT
    //////////////////////////////////////////////////////////////*/

    /// @dev Was: after one burn, EVERY 1271 read in the transaction returned true, unboundedly —
    ///      so a second settlement rode the first one's marker. Two real Permit2 settlements on
    ///      distinct nonces landed in one transaction.
    ///
    ///      Now: the second `consume` sees the id already spent, knows it is not the burn, and
    ///      poisons the transaction. Only the burning settlement is tolerated.
    function test_F1_aSecondSettlementCannotRideTheFirstsBurn() public {
        uint256 fresh = 0xF00D;
        ConfigId cfg = ConfigId.wrap(keccak256("fresh"));
        vm.prank(multiplexer);
        policy.initializeWithMultiplexer(account, cfg, abi.encodePacked(bytes32(fresh)));

        // settlement 1 burns
        vm.prank(account);
        policy.consume(fresh);

        assertTrue(_read(cfg), "settlement 1 check #2 must still be tolerated");

        // settlement 2 carries its own injected consume, as every settlement does
        vm.prank(account);
        policy.consume(fresh);

        assertFalse(_read(cfg), "settlement 2 must be refused");
        assertFalse(_read(cfg), "...and stay refused");
    }

    /*//////////////////////////////////////////////////////////////
                  F2 — A STALE consume CANNOT RESURRECT A SESSION
    //////////////////////////////////////////////////////////////*/

    /// @dev Was: `_markThisTx` ran above the already-burned early return, so a no-op `consume` on
    ///      a session spent in an earlier transaction re-opened its 1271 gate.
    function test_F2_reConsumingASpentIdDoesNotReopenTheGate() public {
        assertFalse(_read(cfgA), "baseline: the spent session is refused");

        vm.prank(account);
        policy.consume(ID_A);

        assertFalse(_read(cfgA), "a stale consume must not resurrect it");
    }

    /*//////////////////////////////////////////////////////////////
                 F3 — ONE SESSION CANNOT BURN ANOTHER'S ID
    //////////////////////////////////////////////////////////////*/

    /// @dev Was: `checkAction` discarded `target` and `data`, so session B — authorised to call
    ///      `consume` — passed session A's id and killed it permanently, for free.
    function test_F3_aSessionMayNotAuthoriseBurningAnotherSessionsId() public {
        bytes memory burnSomeoneElse = abi.encodeCall(IOneTimeUseIdPolicy.consume, (ID_A));

        vm.prank(multiplexer);
        uint256 result = policy.checkAction(cfgB, account, address(policy), 0, burnSomeoneElse);

        assertEq(result, VALIDATION_FAILED, "session B may not burn session A's id");
    }

    /// @dev CONTROL: session B burning its OWN id is exactly what it is for.
    function test_F3_control_aSessionMayBurnItsOwnId() public {
        bytes memory burnOwn = abi.encodeCall(IOneTimeUseIdPolicy.consume, (ID_B));

        vm.prank(multiplexer);
        uint256 result = policy.checkAction(cfgB, account, address(policy), 0, burnOwn);

        assertEq(result, VALIDATION_SUCCESS, "its own id is permitted");
    }

    /// @dev ...and an unrelated action is untouched by the binding
    function test_F3_control_anUnrelatedActionIsUnaffected() public {
        vm.prank(multiplexer);
        uint256 result = policy.checkAction(cfgB, account, makeAddr("someToken"), 0, hex"a9059cbb");

        assertEq(result, VALIDATION_SUCCESS, "the binding only applies to self-calls");
    }

    /*//////////////////////////////////////////////////////////////
                THE COST: EXACTLY ONE consume PER SETTLEMENT
    //////////////////////////////////////////////////////////////*/

    /// @dev The price of the poison rule, asserted rather than described. A settlement carrying
    ///      two `consume` calls refuses itself, so the ops must carry exactly one — pinnable via
    ///      Permit2ClaimPolicy's FIELD_ORIGIN_OPS sub-policy mode.
    function test_aSettlementCarryingTwoConsumesRefusesItself() public {
        uint256 fresh = 0xD00D;
        ConfigId cfg = ConfigId.wrap(keccak256("twice"));
        vm.prank(multiplexer);
        policy.initializeWithMultiplexer(account, cfg, abi.encodePacked(bytes32(fresh)));

        vm.startPrank(account);
        policy.consume(fresh);
        policy.consume(fresh);
        vm.stopPrank();

        assertFalse(_read(cfg), "two consumes in one settlement poison it");
    }
}
