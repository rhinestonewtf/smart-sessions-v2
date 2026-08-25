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

/// @title OneTimeUseIdPolicy.check1271SignedAction Unit Tests
/// @notice Unit tests for the check1271SignedAction function. The two checks of one settlement
///         arrive from DIFFERENT callers and are treated differently:
///
///           pre-claim check  <- the executor : runs BEFORE the burn, so it can only ask
///                                              "is this unspent?"
///           settling check  <- Permit2       : runs AFTER the burn and moves the money, so it
///                                              demands proof that THIS settlement performed it
contract OneTimeUseIdPolicy_check1271SignedAction_Unit_Test is OneTimeUseIdPolicy_Unit_Test {
    /*//////////////////////////////////////////////////////////////
                                 SCOPING
    //////////////////////////////////////////////////////////////*/

    /// @notice Test an unconfigured configId fails closed on both callers
    function test_check1271SignedAction_unconfigured_returnsFalse() external {
        ConfigId never = ConfigId.wrap(keccak256("never"));

        assertFalse(_settlingCheck(never, WITNESS_1), "fails closed for the settling caller");
        assertFalse(_preClaimCheck(never, WITNESS_1), "and for the pre-claim caller");
    }

    /*//////////////////////////////////////////////////////////////
                    THE PRE-CLAIM CHECK - ADVISORY READ
    //////////////////////////////////////////////////////////////*/

    /// @notice Test the pre-claim check passes while the id is unburned
    function test_check1271SignedAction_preClaim_unburned_returnsTrue() external {
        assertTrue(_preClaimCheck(cfgA, WITNESS_1), "pre-claim, nothing burned yet");
    }

    /*//////////////////////////////////////////////////////////////
                       THE SETTLING CHECK - PROOF REQUIRED
    //////////////////////////////////////////////////////////////*/

    /// @notice Test the honest path: pre-claim passes, the burn happens, then the settling check
    function test_check1271SignedAction_honestSettlement_completes() external {
        assertTrue(_preClaimCheck(cfgA, WITNESS_1), "pre-claim, nothing burned yet");

        _consumeFor(ID_A, WITNESS_1);

        assertTrue(_settlingCheck(cfgA, WITNESS_1), "settling check, proof presented");
    }

    /// @notice Test the settling check accepts proof from its own burn in the same transaction
    function test_check1271SignedAction_settlingCheck_acceptsProofFromItsOwnBurn() external {
        _consumeFor(ID_A, WITNESS_1);

        assertTrue(
            _settlingCheck(cfgA, WITNESS_1), "a settlement must not be refused by its own burn"
        );
    }

    /// @notice Test a signature too short to carry a nonce is refused
    function test_check1271SignedAction_shortBlobIsRefused() external {
        _consumeFor(ID_A, WITNESS_1);

        vm.prank(multiplexer);
        assertFalse(
            policy.check1271SignedAction(cfgA, PERMIT2, account, bytes32(0), hex"1234"),
            "a blob too short to carry a nonce cannot prove anything"
        );
    }

    /// @notice Test a second settlement cannot ride the first settlement's burn
    function test_check1271SignedAction_secondSettlementCannotRideTheFirstsBurn() external {
        _consumeFor(ID_A, WITNESS_1);
        assertTrue(_settlingCheck(cfgA, WITNESS_1), "settlement one completes");

        // Settlement two, different nonce, same transaction, never calls consumeFor itself.
        assertFalse(_settlingCheck(cfgA, WITNESS_2), "settlement two cannot ride it");
    }

    /// @notice Test re-consuming an already-burned id clears the nomination instead of reissuing it
    function test_check1271SignedAction_secondSettlementCannotRenominateItself() external {
        _consumeFor(ID_A, WITNESS_1);
        _consumeFor(ID_A, WITNESS_2);

        assertFalse(_settlingCheck(cfgA, WITNESS_2), "a repeat consumeFor nominates nothing");
        assertFalse(_settlingCheck(cfgA, WITNESS_1), "and revokes the original nomination");
    }

    /// @notice Test a settlement that never performs its burn cannot settle
    function test_check1271SignedAction_skippedBurnCannotSettle() external {
        assertTrue(_preClaimCheck(cfgA, WITNESS_1), "the pre-claim check still passes");

        // ...and then the burn never happens.

        assertFalse(_settlingCheck(cfgA, WITNESS_1), "so the settlement cannot complete");
    }

    /// @notice Test a burn nominating a different settlement's witness does not count
    function test_check1271SignedAction_burnNominatingAnotherSettlementDoesNotCount() external {
        _consumeFor(ID_A, WITNESS_2);

        assertFalse(_settlingCheck(cfgA, WITNESS_1), "the nomination must name THIS settlement");
    }

    /// @notice Test an executor-route consumeFor that checkAction refused leaves nothing to ride
    function test_check1271SignedAction_refusedNominationLeavesNothingToSettle() external {
        bytes memory nominate = abi.encodeCall(IOneTimeUseIdPolicy.consumeFor, (ID_A, WITNESS_1));

        uint256 result = _checkAction(cfgA, address(policy), nominate);

        assertEq(result, FAILED, "the executor route cannot nominate");
        assertFalse(_settlingCheck(cfgA, WITNESS_1), "a starved settlement has nothing to ride");
    }

    /// @notice Test a caller that is neither Permit2 nor the executor is refused while unspent
    function test_check1271SignedAction_unknownCaller_failsClosed() external {
        address compact = makeAddr("theCompact");

        vm.prank(multiplexer);
        assertFalse(
            policy.check1271SignedAction(cfgA, compact, account, bytes32(0), _blob(WITNESS_1)),
            "an unknown route (e.g. Compact) must fail closed even while unspent"
        );
    }

    /*//////////////////////////////////////////////////////////////
                                  SHAPE
    //////////////////////////////////////////////////////////////*/

    /// @notice Test Permit2 nonce zero is a valid settlement witness
    function test_check1271SignedAction_permit2NonceZero_canSettle() external {
        _consumeFor(ID_A, 0);

        assertTrue(_settlingCheck(cfgA, 0), "nonce zero is a valid settlement");
    }

    /// @notice Test the max uint256 nonce is a valid settlement witness
    function test_check1271SignedAction_maxNonce_canSettle() external {
        _consumeFor(ID_A, type(uint256).max);

        assertTrue(_settlingCheck(cfgA, type(uint256).max), "the max nonce is a valid settlement");
    }
}

/// @title The cross-transaction half of the settling check's tolerance
/// @notice Split into its own contract deliberately. Transient storage survives every call
///         inside one test body - a forge test body IS one transaction - but it IS cleared
///         between `setUp` and the body. Burning in `setUp` is therefore the only way to observe
///         a LATER transaction.
contract OneTimeUseIdPolicy_check1271SignedAction_CrossTransaction_Unit_Test is Test {
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

    function _blob(uint256 nonce) internal pure returns (bytes memory) {
        return abi.encodePacked(address(0xA4B17E4), bytes32(nonce), bytes32(uint256(9)));
    }

    /// @notice Test the same proof that was tolerated inside the burning transaction is refused
    /// later
    function test_check1271SignedAction_crossTransactionBurnIsRefused() external {
        vm.prank(multiplexer);
        bool ok = policy.check1271SignedAction(cfg, PERMIT2, account, bytes32(0), _blob(WITNESS));

        assertFalse(ok, "a later transaction must be refused");
    }
}
