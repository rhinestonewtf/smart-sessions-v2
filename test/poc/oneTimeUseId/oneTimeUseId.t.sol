// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";

import { OneTimeUseIdPolicy } from "@policies/onetime/OneTimeUseIdPolicy.sol";
import { IOneTimeUseIdPolicy } from "@policies/onetime/interfaces/IOneTimeUseIdPolicy.sol";
import { IActionPolicy, I1271Policy } from "@smartsessions/interfaces/IPolicy.sol";

import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";
import { ConfigId } from "@smartsessions/DataTypes.sol";
import { VALIDATION_SUCCESS, VALIDATION_FAILED } from "erc7579/interfaces/IERC7579Module.sol";

/// @title OneTimeUseIdPolicy — the properties, in isolation
/// @notice The settlement layers appear nowhere in this file, which is the point: this policy
///         bounds a session without knowing what settles it.
contract OneTimeUseId_Test is Test {
    OneTimeUseIdPolicy internal policy;

    address internal multiplexer = makeAddr("multiplexer");
    address internal account = makeAddr("account");

    /// @dev Installing on EVERY action is the requirement, and SmartSessions gives each action
    ///      slot its OWN ConfigId. Two of them here, because the record has to agree across them
    /// —
    ///      keying state on ConfigId is the bug this design inherits a lesson about.
    ConfigId internal cfgA = ConfigId.wrap(keccak256("action.slot.A"));
    ConfigId internal cfgB = ConfigId.wrap(keccak256("action.slot.B"));

    uint256 internal constant ID = 0xBEEF;

    function setUp() public {
        policy = new OneTimeUseIdPolicy(ISignatureTransfer(PERMIT2));
        _install(cfgA, ID);
        _install(cfgB, ID);
    }

    function _install(ConfigId cfg, uint256 id) internal {
        vm.prank(multiplexer);
        policy.initializeWithMultiplexer(account, cfg, abi.encodePacked(bytes32(id)));
    }

    /// @dev What the action surface does for one execution in a settlement batch
    function _validate(ConfigId cfg) internal returns (uint256) {
        vm.prank(multiplexer);
        return policy.checkAction(cfg, account, address(0), 0, "");
    }

    /// @dev The injected execution: the ACCOUNT calls the policy
    address internal constant PERMIT2 = 0x000000000022D473030F116dDEE9F6B43aC78BA3;
    uint256 internal constant WITNESS = 1337;

    function _settlementBurns(uint256 id) internal {
        vm.prank(account);
        policy.consume(id, WITNESS);
    }

    /// @dev A claim blob shaped like `Permit2ClaimPolicy`'s: arbiter(20) ‖ nonce(32) ‖ …
    function _blob(uint256 nonce) internal pure returns (bytes memory) {
        return abi.encodePacked(address(0xA4B17E4), bytes32(nonce), bytes32(uint256(9)));
    }

    /*//////////////////////////////////////////////////////////////
                            THE CORE PROPERTY
    //////////////////////////////////////////////////////////////*/

    function test_theFirstSettlementValidates() public {
        assertEq(_validate(cfgA), VALIDATION_SUCCESS, "an unburned id must let the batch through");
    }

    function test_afterTheSettlementBurns_noFurtherSettlementValidates() public {
        assertEq(_validate(cfgA), VALIDATION_SUCCESS, "settlement one validates");
        _settlementBurns(ID);

        assertEq(_validate(cfgA), VALIDATION_FAILED, "settlement two must be refused");
    }

    /// @dev The record is shared across action SLOTS. Each slot has its own ConfigId, so a design
    ///      that kept the spend under ConfigId would let a settlement using slot B ignore a burn
    ///      recorded under slot A.
    function test_theBurnIsVisibleFromEveryActionSlot() public {
        _settlementBurns(ID);

        assertEq(_validate(cfgA), VALIDATION_FAILED, "slot A sees the burn");
        assertEq(_validate(cfgB), VALIDATION_FAILED, "slot B sees the same burn");
    }

    /*//////////////////////////////////////////////////////////////
              READ HERE, BURN THERE — THE REASON checkAction IS READ-ONLY
    //////////////////////////////////////////////////////////////*/

    /// @dev THE property the read-only split exists for. Pre-claim ops carry more than one
    ///      execution, so the action surface runs more than once per settlement. A burning
    ///      `checkAction` would refuse the second execution of the settlement it just authorized.
    function test_aBatchOfManyExecutionsValidatesEveryOne() public {
        for (uint256 i; i < 8; ++i) {
            assertEq(
                _validate(i % 2 == 0 ? cfgA : cfgB),
                VALIDATION_SUCCESS,
                "every execution in one settlement must validate"
            );
        }
    }

    /// @dev Stated directly, so a future change that makes `checkAction` write breaks here with a
    ///      name that says why.
    function test_checkActionDoesNotBurn() public {
        _validate(cfgA);

        assertFalse(policy.isConsumed(account, ID), "validation must not consume the id");
    }

    /*//////////////////////////////////////////////////////////////
                              THE BURN SITE
    //////////////////////////////////////////////////////////////*/

    /// @dev A settlement may carry more than one `consume`; a revert would fail that settlement
    function test_consumeIsIdempotent() public {
        _settlementBurns(ID);
        _settlementBurns(ID);

        assertTrue(policy.isConsumed(account, ID), "still burned, no revert");
    }

    /// @dev `consume` trusts msg.sender and nothing else, so a third party cannot burn for someone
    ///      else — they can only ever burn their own record.
    function test_aStrangerCannotBurnAnotherAccountsId() public {
        address stranger = makeAddr("stranger");

        vm.prank(stranger);
        policy.consume(ID, WITNESS);

        assertFalse(policy.isConsumed(account, ID), "the account's id is untouched");
        assertEq(_validate(cfgA), VALIDATION_SUCCESS, "and its session still settles");
    }

    function test_theBurnIsPerId() public {
        _settlementBurns(ID + 1);

        assertEq(_validate(cfgA), VALIDATION_SUCCESS, "burning another id does not spend this one");
    }

    /*//////////////////////////////////////////////////////////////
                                  INIT
    //////////////////////////////////////////////////////////////*/

    function test_unconfigured_refused() public {
        ConfigId never = ConfigId.wrap(keccak256("never.installed"));

        assertEq(_validate(never), VALIDATION_FAILED, "an unconfigured slot fails closed");
    }

    /// @dev Zero would be indistinguishable from "no id" for any caller reading `getId`
    function test_theZeroIdIsRejected() public {
        vm.prank(multiplexer);
        vm.expectRevert(IOneTimeUseIdPolicy.InvalidId.selector);
        policy.initializeWithMultiplexer(
            account, ConfigId.wrap(keccak256("zero")), abi.encodePacked(bytes32(0))
        );
    }

    function test_initDataMustBeExactlyOneWord() public {
        vm.prank(multiplexer);
        vm.expectRevert(
            abi.encodeWithSelector(IOneTimeUseIdPolicy.InvalidInitDataLength.selector, uint256(31))
        );
        policy.initializeWithMultiplexer(account, ConfigId.wrap(keccak256("short")), new bytes(31));
    }

    /// @dev Config is keyed on the caller, so a rogue direct install cannot collide with the one
    ///      SmartSessions made
    function test_anotherMultiplexerSeesNothing() public {
        address rogue = makeAddr("rogue");

        vm.prank(rogue);
        uint256 result = policy.checkAction(cfgA, account, address(0), 0, "");

        assertEq(result, VALIDATION_FAILED, "a different multiplexer has no configuration");
    }

    /// @dev A re-enable on a BURNED id yields a session that cannot settle. Denial, never a second
    ///      spend — the record is deliberately never cleared.
    function test_reEnablingOnABurnedIdDoesNotRestoreTheSpend() public {
        _settlementBurns(ID);
        _install(cfgA, ID);

        assertEq(_validate(cfgA), VALIDATION_FAILED, "a stale pin denies");
    }

    function test_reEnablingOnAFreshIdSettlesAgain() public {
        _settlementBurns(ID);
        _install(cfgA, ID + 99);

        assertEq(_validate(cfgA), VALIDATION_SUCCESS, "a fresh pin is a fresh spend");
    }

    /*//////////////////////////////////////////////////////////////
                              BOTH SURFACES
    //////////////////////////////////////////////////////////////*/

    function test_servesBothPolicySurfaces() public view {
        assertTrue(policy.supportsInterface(type(IActionPolicy).interfaceId), "action surface");
        assertTrue(policy.supportsInterface(type(I1271Policy).interfaceId), "1271 surface");
    }

    function test_advertisesItsOwnViewSurface() public view {
        assertTrue(policy.supportsInterface(type(IOneTimeUseIdPolicy).interfaceId));
    }
    /*//////////////////////////////////////////////////////////////
                     THE SAME-TRANSACTION TOLERANCE
    //////////////////////////////////////////////////////////////*/

    function _read1271(ConfigId c) internal returns (bool) {
        vm.prank(multiplexer);
        return policy.check1271SignedAction(c, PERMIT2, account, bytes32(0), _blob(WITNESS));
    }

    /// @dev The arbiter route reads 1271 AFTER the pre-claim ops burned, in the same transaction.
    ///      A strict read would refuse the settlement that just burned. This is the case that
    ///      makes the Permit2 family work at all.
    function test_theSettlingCheckAcceptsProofFromItsOwnBurn() public {
        _settlementBurns(ID);

        assertTrue(_read1271(cfgA), "a settlement must not be refused by its own burn");
    }

    /// @dev The action surface never needs that tolerance — action policies run before any
    ///      execution in the batch — so it stays strict. A Permit2 settlement riding in the same
    ///      transaction is a SECOND spend, not a second execution of one.
    function test_checkActionStaysStrictEvenInTheSameTransaction() public {
        _settlementBurns(ID);

        assertEq(_validate(cfgA), VALIDATION_FAILED, "the action surface does not tolerate");
    }
}

/// @title The cross-transaction half of the tolerance
/// @notice Split into its own contract deliberately. Transient storage survives every call inside
///         one test body — a forge test body IS one transaction — but it IS cleared between
///         `setUp` and the body. Burning in `setUp` is therefore the only way to observe a LATER
///         transaction, and without this split the tolerance would be indistinguishable from no
///         protection at all.
contract OneTimeUseId_AcrossTransactions_Test is Test {
    OneTimeUseIdPolicy internal policy;

    address internal multiplexer = makeAddr("multiplexer");
    address internal account = makeAddr("account");

    ConfigId internal cfg = ConfigId.wrap(keccak256("action.slot.A"));
    uint256 internal constant ID = 0xBEEF;

    address internal constant PERMIT2 = 0x000000000022D473030F116dDEE9F6B43aC78BA3;
    uint256 internal constant WITNESS = 1337;

    function _blob(uint256 nonce) internal pure returns (bytes memory) {
        return abi.encodePacked(address(0xA4B17E4), bytes32(nonce), bytes32(uint256(9)));
    }

    /// @dev Settlement one happens HERE, so the test body is a different transaction
    function setUp() public {
        policy = new OneTimeUseIdPolicy(ISignatureTransfer(PERMIT2));

        vm.prank(multiplexer);
        policy.initializeWithMultiplexer(account, cfg, abi.encodePacked(bytes32(ID)));

        vm.prank(account);
        policy.consume(ID, WITNESS);
    }

    /// @dev THE property. The same read that was tolerated inside the burning transaction refuses.
    function test_theSettlingCheckRefusesABurnFromAnEarlierTransaction() public {
        vm.prank(multiplexer);
        bool ok = policy.check1271SignedAction(cfg, PERMIT2, account, bytes32(0), _blob(WITNESS));

        assertFalse(ok, "a later transaction must be refused");
    }

    function test_theActionSurfaceAlsoRefuses() public {
        vm.prank(multiplexer);
        assertEq(
            policy.checkAction(cfg, account, address(0), 0, ""),
            VALIDATION_FAILED,
            "and so does the action surface"
        );
    }

    /// @dev Guards the split itself: the durable burn must survive setUp, or the two tests above
    ///      would be passing because nothing happened rather than because the tolerance expired.
    function test_theDurableBurnSurvivesSetUp() public view {
        assertTrue(policy.isConsumed(account, ID), "the durable record crossed the boundary");
    }
}
