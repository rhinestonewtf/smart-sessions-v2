// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";

import { PeriodicLimitPolicy } from "@policies/periodic/PeriodicLimitPolicy.sol";
import { IPeriodicLimitPolicy } from "@policies/periodic/interfaces/IPeriodicLimitPolicy.sol";
import { IActionPolicy, IPolicy } from "@smartsessions/interfaces/IPolicy.sol";
import { IERC165 } from "@openzeppelin/contracts/interfaces/IERC165.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import { ConfigId } from "@smartsessions/DataTypes.sol";
import { VALIDATION_SUCCESS, VALIDATION_FAILED } from "erc7579/interfaces/IERC7579Module.sol";

contract PeriodicLimitPolicy_Unit_Test is Test {
    PeriodicLimitPolicy internal policy;

    address internal multiplexer = makeAddr("multiplexer");
    address internal account = makeAddr("account");
    address internal token = makeAddr("token");
    address internal merchant = makeAddr("merchant");
    ConfigId internal configId = ConfigId.wrap(keccak256("config"));

    uint48 internal constant PERIOD = 30 days;
    uint48 internal constant START = 1_000_000;

    function setUp() public {
        policy = new PeriodicLimitPolicy();
        vm.warp(START);
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    function _config(
        IPeriodicLimitPolicy.PeriodMode mode,
        uint32 maxUses,
        uint256 maxAmount
    )
        internal
        view
        returns (IPeriodicLimitPolicy.PeriodicLimitConfig memory)
    {
        return IPeriodicLimitPolicy.PeriodicLimitConfig({
            mode: mode,
            period: PERIOD,
            start: START,
            maxUses: maxUses,
            token: maxAmount == 0 ? address(0) : token,
            maxAmount: maxAmount
        });
    }

    function _install(IPeriodicLimitPolicy.PeriodicLimitConfig memory config) internal {
        vm.prank(multiplexer);
        policy.initializeWithMultiplexer(account, configId, abi.encode(config));
    }

    function _transfer(uint256 amount) internal view returns (bytes memory) {
        return abi.encodeCall(IERC20.transfer, (merchant, amount));
    }

    function _check(address target, uint256 value, bytes memory data) internal returns (uint256) {
        vm.prank(multiplexer);
        return policy.checkAction(configId, account, target, value, data);
    }

    function _charge(uint256 amount) internal returns (uint256) {
        return _check(token, 0, _transfer(amount));
    }

    /*//////////////////////////////////////////////////////////////
                                  INIT
    //////////////////////////////////////////////////////////////*/

    function test_initialize_storesConfig() public {
        _install(_config(IPeriodicLimitPolicy.PeriodMode.Fixed, 1, 10e6));

        IPeriodicLimitPolicy.PeriodicLimitConfig memory stored =
            policy.getConfig(configId, multiplexer, account);
        assertEq(uint8(stored.mode), uint8(IPeriodicLimitPolicy.PeriodMode.Fixed));
        assertEq(stored.period, PERIOD);
        assertEq(stored.start, START);
        assertEq(stored.maxUses, 1);
        assertEq(stored.token, token);
        assertEq(stored.maxAmount, 10e6);
    }

    function test_initialize_zeroStartMeansNow() public {
        IPeriodicLimitPolicy.PeriodicLimitConfig memory config =
            _config(IPeriodicLimitPolicy.PeriodMode.Fixed, 1, 0);
        config.start = 0;
        vm.warp(START + 5);
        _install(config);

        assertEq(policy.getConfig(configId, multiplexer, account).start, START + 5);
    }

    function test_initialize_RevertWhen_wrongLength() public {
        bytes memory initData = abi.encode(_config(IPeriodicLimitPolicy.PeriodMode.Fixed, 1, 0));
        vm.prank(multiplexer);
        vm.expectRevert(
            abi.encodeWithSelector(IPeriodicLimitPolicy.InvalidInitDataLength.selector, 160)
        );
        policy.initializeWithMultiplexer(account, configId, _slice(initData, 160));
    }

    function test_initialize_RevertWhen_zeroPeriod() public {
        IPeriodicLimitPolicy.PeriodicLimitConfig memory config =
            _config(IPeriodicLimitPolicy.PeriodMode.Fixed, 1, 0);
        config.period = 0;
        vm.prank(multiplexer);
        vm.expectRevert(IPeriodicLimitPolicy.InvalidPeriod.selector);
        policy.initializeWithMultiplexer(account, configId, abi.encode(config));
    }

    function test_initialize_RevertWhen_noLimit() public {
        vm.prank(multiplexer);
        vm.expectRevert(IPeriodicLimitPolicy.NoLimitSet.selector);
        policy.initializeWithMultiplexer(
            account, configId, abi.encode(_config(IPeriodicLimitPolicy.PeriodMode.Fixed, 0, 0))
        );
    }

    function test_initialize_RevertWhen_amountWithoutToken() public {
        IPeriodicLimitPolicy.PeriodicLimitConfig memory config =
            _config(IPeriodicLimitPolicy.PeriodMode.Fixed, 1, 10e6);
        config.token = address(0);
        vm.prank(multiplexer);
        vm.expectRevert(
            abi.encodeWithSelector(IPeriodicLimitPolicy.InvalidToken.selector, address(0), 10e6)
        );
        policy.initializeWithMultiplexer(account, configId, abi.encode(config));
    }

    function test_initialize_RevertWhen_tokenWithoutAmount() public {
        IPeriodicLimitPolicy.PeriodicLimitConfig memory config =
            _config(IPeriodicLimitPolicy.PeriodMode.Fixed, 1, 0);
        config.token = token;
        vm.prank(multiplexer);
        vm.expectRevert(
            abi.encodeWithSelector(IPeriodicLimitPolicy.InvalidToken.selector, token, 0)
        );
        policy.initializeWithMultiplexer(account, configId, abi.encode(config));
    }

    function test_initialize_RevertWhen_modeOutOfRange() public {
        bytes memory initData = abi.encode(_config(IPeriodicLimitPolicy.PeriodMode.Fixed, 1, 0));
        assembly {
            mstore(add(initData, 0x20), 2)
        }
        vm.prank(multiplexer);
        vm.expectRevert();
        policy.initializeWithMultiplexer(account, configId, initData);
    }

    function test_initialize_reinstallKeepsUsage() public {
        _install(_config(IPeriodicLimitPolicy.PeriodMode.Fixed, 1, 0));
        assertEq(_charge(1), VALIDATION_SUCCESS);

        _install(_config(IPeriodicLimitPolicy.PeriodMode.Fixed, 1, 0));
        assertEq(_charge(1), VALIDATION_FAILED, "a re-enable must not open a fresh window");
    }

    /*//////////////////////////////////////////////////////////////
                              FIXED WINDOWS
    //////////////////////////////////////////////////////////////*/

    function test_fixed_oneUsePerWindow() public {
        _install(_config(IPeriodicLimitPolicy.PeriodMode.Fixed, 1, 0));

        assertEq(_charge(1), VALIDATION_SUCCESS);
        assertEq(_charge(1), VALIDATION_FAILED);

        vm.warp(START + PERIOD - 1);
        assertEq(_charge(1), VALIDATION_FAILED);

        vm.warp(START + PERIOD);
        assertEq(_charge(1), VALIDATION_SUCCESS);
        assertEq(_charge(1), VALIDATION_FAILED);
    }

    function test_fixed_lateUseDoesNotMoveNextWindow() public {
        _install(_config(IPeriodicLimitPolicy.PeriodMode.Fixed, 1, 0));

        vm.warp(START + PERIOD - 1);
        assertEq(_charge(1), VALIDATION_SUCCESS);

        vm.warp(START + PERIOD);
        assertEq(_charge(1), VALIDATION_SUCCESS, "next window opens on schedule");
    }

    function test_fixed_skippedWindowsDoNotAccumulate() public {
        _install(_config(IPeriodicLimitPolicy.PeriodMode.Fixed, 1, 0));

        vm.warp(START + 3 * uint256(PERIOD) + 7);
        assertEq(_charge(1), VALIDATION_SUCCESS);
        assertEq(_charge(1), VALIDATION_FAILED);
    }

    function test_fixed_failsBeforeStart() public {
        IPeriodicLimitPolicy.PeriodicLimitConfig memory config =
            _config(IPeriodicLimitPolicy.PeriodMode.Fixed, 1, 0);
        config.start = START + 1 days;
        _install(config);

        assertEq(_charge(1), VALIDATION_FAILED);
        vm.warp(START + 1 days);
        assertEq(_charge(1), VALIDATION_SUCCESS);
    }

    function test_fixed_multipleUsesPerWindow() public {
        _install(_config(IPeriodicLimitPolicy.PeriodMode.Fixed, 3, 0));

        assertEq(_charge(1), VALIDATION_SUCCESS);
        assertEq(_charge(1), VALIDATION_SUCCESS);
        assertEq(_charge(1), VALIDATION_SUCCESS);
        assertEq(_charge(1), VALIDATION_FAILED);
    }

    /*//////////////////////////////////////////////////////////////
                           FROM-FIRST-USE WINDOWS
    //////////////////////////////////////////////////////////////*/

    function test_fromFirstUse_usesAreAPeriodApart() public {
        _install(_config(IPeriodicLimitPolicy.PeriodMode.FromFirstUse, 1, 0));

        vm.warp(START + 10 days);
        assertEq(_charge(1), VALIDATION_SUCCESS);

        // A fixed window would have reopened at START + PERIOD.
        vm.warp(START + PERIOD);
        assertEq(_charge(1), VALIDATION_FAILED);

        vm.warp(START + 10 days + PERIOD - 1);
        assertEq(_charge(1), VALIDATION_FAILED);

        vm.warp(START + 10 days + PERIOD);
        assertEq(_charge(1), VALIDATION_SUCCESS);
    }

    function test_fromFirstUse_lateUseMovesNextWindow() public {
        _install(_config(IPeriodicLimitPolicy.PeriodMode.FromFirstUse, 1, 0));
        assertEq(_charge(1), VALIDATION_SUCCESS);

        vm.warp(START + 2 * uint256(PERIOD) + 5 days);
        assertEq(_charge(1), VALIDATION_SUCCESS);

        vm.warp(START + 3 * uint256(PERIOD));
        assertEq(_charge(1), VALIDATION_FAILED, "window runs from the late use");
    }

    function test_fromFirstUse_failsBeforeStart() public {
        IPeriodicLimitPolicy.PeriodicLimitConfig memory config =
            _config(IPeriodicLimitPolicy.PeriodMode.FromFirstUse, 1, 0);
        config.start = START + 1 days;
        _install(config);

        assertEq(_charge(1), VALIDATION_FAILED);
    }

    /*//////////////////////////////////////////////////////////////
                              AMOUNT LIMIT
    //////////////////////////////////////////////////////////////*/

    function test_amount_capsTheWindowTotal() public {
        _install(_config(IPeriodicLimitPolicy.PeriodMode.Fixed, 0, 10e6));

        assertEq(_charge(6e6), VALIDATION_SUCCESS);
        assertEq(_charge(5e6), VALIDATION_FAILED);
        assertEq(_charge(4e6), VALIDATION_SUCCESS);
        assertEq(_charge(1), VALIDATION_FAILED);

        vm.warp(START + PERIOD);
        assertEq(_charge(10e6), VALIDATION_SUCCESS);
    }

    function test_amount_andUsesBothBind() public {
        _install(_config(IPeriodicLimitPolicy.PeriodMode.Fixed, 1, 10e6));

        assertEq(_charge(11e6), VALIDATION_FAILED, "over the amount");
        assertEq(_charge(10e6), VALIDATION_SUCCESS);
        assertEq(_charge(0), VALIDATION_FAILED, "over the uses");
    }

    function test_amount_countsTransferFrom() public {
        _install(_config(IPeriodicLimitPolicy.PeriodMode.Fixed, 0, 10e6));

        bytes memory data = abi.encodeCall(IERC20.transferFrom, (account, merchant, 10e6));
        assertEq(_check(token, 0, data), VALIDATION_SUCCESS);
        assertEq(_charge(1), VALIDATION_FAILED);
    }

    function test_amount_refusesApprove() public {
        _install(_config(IPeriodicLimitPolicy.PeriodMode.Fixed, 0, 10e6));

        bytes memory data = abi.encodeCall(IERC20.approve, (merchant, 1));
        assertEq(_check(token, 0, data), VALIDATION_FAILED);
    }

    function test_amount_refusesOtherToken() public {
        _install(_config(IPeriodicLimitPolicy.PeriodMode.Fixed, 0, 10e6));
        assertEq(_check(makeAddr("other"), 0, _transfer(1)), VALIDATION_FAILED);
    }

    function test_amount_refusesNativeValue() public {
        _install(_config(IPeriodicLimitPolicy.PeriodMode.Fixed, 0, 10e6));
        assertEq(_check(token, 1, _transfer(1)), VALIDATION_FAILED);
    }

    function test_amount_refusesShortCalldata() public {
        _install(_config(IPeriodicLimitPolicy.PeriodMode.Fixed, 0, 10e6));

        bytes memory data = _slice(_transfer(1), 67);
        assertEq(_check(token, 0, data), VALIDATION_FAILED);
        assertEq(_check(token, 0, hex"a9059c"), VALIDATION_FAILED);
    }

    function test_amount_maxUintFailsWithoutReverting() public {
        _install(_config(IPeriodicLimitPolicy.PeriodMode.Fixed, 0, 10e6));
        assertEq(_charge(1), VALIDATION_SUCCESS);
        assertEq(_charge(type(uint256).max), VALIDATION_FAILED);
    }

    function test_usesOnly_admitsAnyCall() public {
        _install(_config(IPeriodicLimitPolicy.PeriodMode.Fixed, 1, 0));
        assertEq(_check(makeAddr("anything"), 1 ether, hex""), VALIDATION_SUCCESS);
    }

    /*//////////////////////////////////////////////////////////////
                               ISOLATION
    //////////////////////////////////////////////////////////////*/

    function test_failsWhenNotInstalled() public {
        assertEq(_charge(1), VALIDATION_FAILED);
    }

    function test_countersAreKeyedByMultiplexerAndAccount() public {
        _install(_config(IPeriodicLimitPolicy.PeriodMode.Fixed, 1, 0));
        assertEq(_charge(1), VALIDATION_SUCCESS);

        vm.prank(makeAddr("otherMultiplexer"));
        assertEq(
            policy.checkAction(configId, account, token, 0, _transfer(1)),
            VALIDATION_FAILED,
            "not installed under another multiplexer"
        );

        vm.prank(multiplexer);
        assertEq(
            policy.checkAction(configId, makeAddr("otherAccount"), token, 0, _transfer(1)),
            VALIDATION_FAILED,
            "not installed for another account"
        );
    }

    /*//////////////////////////////////////////////////////////////
                                 VIEWS
    //////////////////////////////////////////////////////////////*/

    function test_currentUsage_fixed() public {
        _install(_config(IPeriodicLimitPolicy.PeriodMode.Fixed, 2, 10e6));
        vm.warp(START + 1 days);

        (uint48 windowStart, uint256 uses, uint256 spent) =
            policy.currentUsage(configId, multiplexer, account);
        assertEq(windowStart, START);
        assertEq(uses, 0);
        assertEq(spent, 0);

        _charge(3e6);
        (windowStart, uses, spent) = policy.currentUsage(configId, multiplexer, account);
        assertEq(windowStart, START);
        assertEq(uses, 1);
        assertEq(spent, 3e6);

        vm.warp(START + PERIOD + 1);
        (windowStart, uses, spent) = policy.currentUsage(configId, multiplexer, account);
        assertEq(windowStart, START + PERIOD);
        assertEq(uses, 0);
        assertEq(spent, 0);
    }

    function test_currentUsage_fromFirstUse() public {
        _install(_config(IPeriodicLimitPolicy.PeriodMode.FromFirstUse, 1, 0));

        (uint48 windowStart, uint256 uses,) = policy.currentUsage(configId, multiplexer, account);
        assertEq(windowStart, 0, "no window before the first use");
        assertEq(uses, 0);

        vm.warp(START + 3 days);
        _charge(1);
        (windowStart, uses,) = policy.currentUsage(configId, multiplexer, account);
        assertEq(windowStart, START + 3 days);
        assertEq(uses, 1);

        vm.warp(START + 3 days + PERIOD);
        (windowStart, uses,) = policy.currentUsage(configId, multiplexer, account);
        assertEq(windowStart, 0);
        assertEq(uses, 0);
    }

    function test_supportsInterface() public view {
        assertTrue(policy.supportsInterface(type(IActionPolicy).interfaceId));
        assertTrue(policy.supportsInterface(type(IPolicy).interfaceId));
        assertTrue(policy.supportsInterface(type(IPeriodicLimitPolicy).interfaceId));
        assertTrue(policy.supportsInterface(type(IERC165).interfaceId));
        assertFalse(policy.supportsInterface(0xdeadbeef));
    }

    /*//////////////////////////////////////////////////////////////
                                  FUZZ
    //////////////////////////////////////////////////////////////*/

    /// @dev Whatever the timing, no fixed window ever admits more than its limits
    function testFuzz_fixed_windowNeverExceedsLimits(
        uint32 maxUses,
        uint64 maxAmount,
        uint32[16] memory gaps,
        uint64[16] memory amounts
    )
        public
    {
        maxUses = uint32(bound(maxUses, 1, 4));
        maxAmount = uint64(bound(maxAmount, 1, 100e6));
        _install(_config(IPeriodicLimitPolicy.PeriodMode.Fixed, maxUses, maxAmount));

        uint256 window = type(uint256).max;
        uint256 uses;
        uint256 spent;
        for (uint256 i; i < gaps.length; i++) {
            vm.warp(block.timestamp + bound(gaps[i], 0, 20 days));
            uint256 current = (block.timestamp - START) / PERIOD;
            if (current != window) (window, uses, spent) = (current, 0, 0);

            uint256 amount = bound(amounts[i], 0, maxAmount);
            bool fits = uses < maxUses && spent + amount <= maxAmount;
            assertEq(_charge(amount), fits ? VALIDATION_SUCCESS : VALIDATION_FAILED);
            if (fits) (uses, spent) = (uses + 1, spent + amount);
        }
    }

    /// @dev With one use per window, two admitted uses are always at least a period apart
    function testFuzz_fromFirstUse_usesAtLeastAPeriodApart(uint32[16] memory gaps) public {
        _install(_config(IPeriodicLimitPolicy.PeriodMode.FromFirstUse, 1, 0));

        uint256 last;
        bool used;
        for (uint256 i; i < gaps.length; i++) {
            vm.warp(block.timestamp + bound(gaps[i], 0, 40 days));
            bool expected = !used || block.timestamp >= last + PERIOD;
            assertEq(_charge(1), expected ? VALIDATION_SUCCESS : VALIDATION_FAILED);
            if (expected) (last, used) = (block.timestamp, true);
        }
    }

    function _slice(bytes memory data, uint256 length) internal pure returns (bytes memory out) {
        out = new bytes(length);
        for (uint256 i; i < length; i++) {
            out[i] = data[i];
        }
    }
}
