// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";

import { OneTimeUseIdPolicy } from "@policies/onetime/OneTimeUseIdPolicy.sol";
import { IOneTimeUseIdPolicy } from "@policies/onetime/interfaces/IOneTimeUseIdPolicy.sol";
import { IActionPolicy, I1271Policy } from "@smartsessions/interfaces/IPolicy.sol";

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
        policy = new OneTimeUseIdPolicy();
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
    function _settlementBurns(uint256 id) internal {
        vm.prank(account);
        policy.consume(id);
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
        policy.consume(ID);

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
                        THE DELIBERATE NON-INTERFACE
    //////////////////////////////////////////////////////////////*/

    /// @dev Not an oversight. The Permit2 arbiter route validates ERC-1271 twice with the
    ///      pre-claim execution in between, so a policy on that surface would see its own burn at
    ///      the second check and refuse its own settlement. Not implementing the interface makes
    ///      that configuration unrepresentable — `enable` rejects a policy that does not
    /// advertise
    ///      the type of the slot it is being installed into.
    function test_itIsDeliberatelyNotAn1271Policy() public view {
        assertTrue(policy.supportsInterface(type(IActionPolicy).interfaceId), "action surface");
        assertFalse(
            policy.supportsInterface(type(I1271Policy).interfaceId),
            "must NOT be installable on the 1271 surface"
        );
    }

    function test_advertisesItsOwnViewSurface() public view {
        assertTrue(policy.supportsInterface(type(IOneTimeUseIdPolicy).interfaceId));
    }
}
