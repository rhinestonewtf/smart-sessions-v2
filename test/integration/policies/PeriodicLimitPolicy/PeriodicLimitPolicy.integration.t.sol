// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

// Dependencies
import {
    ActionPolicy_Integration_Test
} from "@test/integration/policies/ActionPolicyBase.integration.t.sol";

// Contracts
import { PeriodicLimitPolicy } from "@policies/periodic/PeriodicLimitPolicy.sol";

// Interfaces
import { IPeriodicLimitPolicy } from "@policies/periodic/interfaces/IPeriodicLimitPolicy.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

// Libraries
import { Execution } from "@compact-utils/common/SmartExecutionLib.sol";

// Types
import { AccountInstance } from "@modulekit/ModuleKit.sol";
import { PermissionId } from "@smartsessions/DataTypes.sol";

/// @title PeriodicLimitPolicy Integration Test
/// @notice One charge per 30 days of at most 10 tokens, validated through SmartSessionEmissary
contract PeriodicLimitPolicy_Integration_Test is ActionPolicy_Integration_Test {
    PeriodicLimitPolicy policy;
    AccountInstance account;

    address token;
    address merchant;
    PermissionId pid;
    uint256 nonce;

    uint48 constant PERIOD = 30 days;

    function setUp() public override {
        super.setUp();

        policy = new PeriodicLimitPolicy();
        account = makeAccountInstance("TestAccount");
        setupAccountWithEmissary(account);

        token = makeAddr("token");
        merchant = makeAddr("merchant");

        bytes memory initData = abi.encode(
            IPeriodicLimitPolicy.PeriodicLimitConfig({
                chainId: uint64(block.chainid),
                mode: IPeriodicLimitPolicy.PeriodMode.Fixed,
                period: PERIOD,
                start: uint48(block.timestamp),
                maxUses: 1,
                token: token,
                maxAmount: 10e6
            })
        );
        pid = enableActionSession(
            account, address(policy), initData, token, IERC20.transfer.selector
        );
    }

    function _charge(uint256 amount) internal returns (bool) {
        bytes memory data = abi.encodeCall(IERC20.transfer, (merchant, amount));
        bytes32 digest = createTestDigest(account.account, token, 0, data, ++nonce);
        return validateExecution(account, pid, digest, token, 0, data);
    }

    function test_verifyExecution_oneChargePerPeriod() public {
        assertTrue(_charge(10e6), "first charge");
        assertFalse(_charge(1), "second charge in the same period");

        vm.warp(block.timestamp + PERIOD);
        assertTrue(_charge(10e6), "charge in the next period");
    }

    /// @dev The policy's refusal makes the multiplexer revert, so nothing it recorded survives
    function test_verifyExecution_refusedChargeDoesNotUseThePeriod() public {
        assertFalse(_charge(10e6 + 1), "over the amount");
        assertTrue(_charge(10e6), "the period is still unused");
    }

    function test_verifyExecution_batchOfTwoChargesIsRefused() public {
        Execution[] memory executions = new Execution[](2);
        executions[0] = createExecution(token, 0, abi.encodeCall(IERC20.transfer, (merchant, 1e6)));
        executions[1] = executions[0];
        bytes32 digest = createBatchTestDigest(account.account, executions, ++nonce);

        assertFalse(validateBatchExecution(account, pid, digest, executions));
        assertTrue(_charge(10e6), "the refused batch left the period unused");
    }
}
