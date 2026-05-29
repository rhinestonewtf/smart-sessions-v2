// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { Test } from "@forge-std/Test.sol";
import { Execution } from "modulekit/integrations/ERC7579Exec.sol";

import { ConfigId } from "@smartsessions/DataTypes.sol";

import {
    IBaseIntentExecutorPolicy
} from "@policies/settlementlayer/shared/interfaces/IBaseIntentExecutorPolicy.sol";
import {
    StaticIntentExecutorPolicy
} from "@policies/settlementlayer/intentExecutorStatic/StaticIntentExecutorPolicy.sol";
import { RelayAdapter } from "@policies/settlementlayer/shared/adapters/RelayAdapter.sol";
import { RhinoAdapter } from "@policies/settlementlayer/shared/adapters/RhinoAdapter.sol";
import { CCTPAdapter } from "@policies/settlementlayer/shared/adapters/CCTPAdapter.sol";
import { RelayCalldataLib } from "@policies/settlementlayer/shared/lib/RelayCalldataLib.sol";
import { RhinoCalldataLib } from "@policies/settlementlayer/shared/lib/RhinoCalldataLib.sol";
import { CCTPCalldataLib } from "@policies/settlementlayer/shared/lib/CCTPCalldataLib.sol";
import { OpsCalldataLib } from "@policies/settlementlayer/shared/lib/OpsCalldataLib.sol";
import { VARIANT_MULTI_CHAIN } from "@policies/settlementlayer/shared/types/IntentExecutorDataTypes.sol";

import { IntentExecutorTestUtils } from "../IntentExecutorTestUtils.sol";

/// @notice Adversarial tests for `StaticIntentExecutorPolicy` deployed against the Relay
///         adapter — exercises the base header parser and the adapter ACL end-to-end with
///         precise revert-selector assertions and fuzz inputs.
contract StaticIntentExecutorPolicy_Relay_Test is Test, IntentExecutorTestUtils {
    StaticIntentExecutorPolicy internal policy;
    RelayAdapter internal adapter;

    ConfigId internal configId = ConfigId.wrap(bytes32(uint256(0x1eef)));
    address internal account;
    address internal intentExecutor;
    address internal relayRouter;
    address internal ieAdapter;
    address internal token;
    address internal otherToken;
    address internal recipient;
    uint256 internal constant MAX_EX_RATE = 1e20;
    uint256 internal constant NONCE = 7;

    function setUp() public {
        adapter = new RelayAdapter();
        policy = new StaticIntentExecutorPolicy(adapter);
        account = makeAddr("account");
        intentExecutor = makeAddr("intentExecutor");
        relayRouter = makeAddr("relayRouter");
        ieAdapter = makeAddr("ieAdapter");
        token = makeAddr("usdc");
        otherToken = makeAddr("dai");
        recipient = makeAddr("recipient");

        bytes memory baseHeader = abi.encodePacked(
            intentExecutor, uint8(0), uint256(MAX_EX_RATE), uint8(1), token
        );
        bytes memory subTail = abi.encodePacked(
            relayRouter, ieAdapter, uint8(1), recipient, uint8(1), token
        );
        policy.initializeWithMultiplexer(account, configId, bytes.concat(baseHeader, subTail));
    }

    /*//////////////////////////////////////////////////////////////
                              HAPPY PATH
    //////////////////////////////////////////////////////////////*/

    function test_happyPath_approveThenMulticall() public view {
        Execution[] memory calls = new Execution[](2);
        calls[0] = _erc20Approve(token, relayRouter, 100);
        calls[1] = _routerCall(RelayCalldataLib.SEL_RELAY_MULTICALL, 0);
        (bytes32 h, bytes memory data) = _build(calls, address(0), 0);
        assertTrue(policy.check1271SignedAction(configId, address(0), account, h, data));
    }

    function test_happyPath_transferToWhitelistedRecipient() public view {
        Execution[] memory calls = new Execution[](1);
        calls[0] = _erc20Transfer(token, recipient, 1);
        (bytes32 h, bytes memory data) = _build(calls, address(0), 0);
        assertTrue(policy.check1271SignedAction(configId, address(0), account, h, data));
    }

    function test_happyPath_routerEthValueAllowed() public view {
        Execution[] memory calls = new Execution[](1);
        calls[0] = _routerCall(RelayCalldataLib.SEL_RELAY_TRANSFER_AND_MULTICALL, 5 ether);
        (bytes32 h, bytes memory data) = _build(calls, address(0), 0);
        assertTrue(policy.check1271SignedAction(configId, address(0), account, h, data));
    }

    function test_happyPath_gasRefundWithinCap() public view {
        Execution[] memory calls = _justRouter();
        bytes32 h = _digest(intentExecutor, account, NONCE, calls, _gasRefundHash(token, MAX_EX_RATE, true));
        bytes memory data = _blobWithGasRefund(account, NONCE, token, MAX_EX_RATE, calls);
        assertTrue(policy.check1271SignedAction(configId, address(0), account, h, data));
    }

    /*//////////////////////////////////////////////////////////////
                            HEADER / VARIANT
    //////////////////////////////////////////////////////////////*/

    function testFuzz_revertWhen_variantNonZero(uint8 variant) public {
        vm.assume(variant != 0);
        Execution[] memory calls = _justRouter();
        (bytes32 h, bytes memory data) = _build(calls, address(0), 0);
        data[0] = bytes1(variant);
        vm.expectRevert(
            abi.encodeWithSelector(IBaseIntentExecutorPolicy.VariantNotSupported.selector, variant)
        );
        policy.check1271SignedAction(configId, address(0), account, h, data);
    }

    function testFuzz_revertWhen_headerTooShort(uint8 cap) public {
        // Strip bytes off the *end* (after building) so we exercise the early-length
        // check on data.length < 54 / 106.
        uint256 keep = cap % 54;
        bytes memory data = new bytes(keep);
        vm.expectRevert(
            abi.encodeWithSelector(IBaseIntentExecutorPolicy.DataTruncated.selector, uint256(54), keep)
        );
        policy.check1271SignedAction(configId, address(0), account, bytes32(0), data);
    }

    function test_revertWhen_gasRefundTruncated() public {
        bytes memory data = new bytes(105);
        data[1] = bytes1(uint8(1));
        for (uint256 i; i < 20; i++) {
            data[2 + i] = bytes1(uint8(uint160(account) >> (8 * (19 - i))));
        }
        vm.expectRevert(
            abi.encodeWithSelector(IBaseIntentExecutorPolicy.DataTruncated.selector, uint256(106), uint256(105))
        );
        policy.check1271SignedAction(configId, address(0), account, bytes32(0), data);
    }

    /*//////////////////////////////////////////////////////////////
                              ACCOUNT
    //////////////////////////////////////////////////////////////*/

    function testFuzz_revertWhen_accountInBlobMismatches(address fake) public {
        vm.assume(fake != account);
        Execution[] memory calls = _justRouter();
        (bytes32 h, bytes memory data) = _build(calls, address(0), 0);
        for (uint256 i; i < 20; i++) {
            data[2 + i] = bytes1(uint8(uint160(fake) >> (8 * (19 - i))));
        }
        vm.expectRevert(
            abi.encodeWithSelector(IBaseIntentExecutorPolicy.AccountMismatch.selector, account, fake)
        );
        policy.check1271SignedAction(configId, address(0), account, h, data);
    }

    /*//////////////////////////////////////////////////////////////
                               DIGEST
    //////////////////////////////////////////////////////////////*/

    function testFuzz_revertWhen_digestForgery(bytes32 fakeHash) public {
        Execution[] memory calls = _justRouter();
        (bytes32 h, bytes memory data) = _build(calls, address(0), 0);
        vm.assume(fakeHash != h);
        vm.expectRevert(IBaseIntentExecutorPolicy.DigestMismatch.selector);
        policy.check1271SignedAction(configId, address(0), account, fakeHash, data);
    }

    function test_revertWhen_nonceTamperedAfterSigning() public {
        Execution[] memory calls = _justRouter();
        (bytes32 h, bytes memory data) = _build(calls, address(0), 0);
        data[53] = bytes1(uint8(data[53]) ^ 0x01);
        vm.expectRevert(IBaseIntentExecutorPolicy.DigestMismatch.selector);
        policy.check1271SignedAction(configId, address(0), account, h, data);
    }

    function test_revertWhen_gasRefundForgedAsNone() public {
        // The signer authorised a real gas refund; an attacker re-encodes the blob to
        // declare none. Digest mismatch must catch this.
        Execution[] memory calls = _justRouter();
        bytes32 hWithRefund =
            _digest(intentExecutor, account, NONCE, calls, _gasRefundHash(token, 5, true));
        bytes memory dataNoRefund = _blobSansGasRefund(account, NONCE, calls);
        vm.expectRevert(IBaseIntentExecutorPolicy.DigestMismatch.selector);
        policy.check1271SignedAction(configId, address(0), account, hWithRefund, dataNoRefund);
    }

    /*//////////////////////////////////////////////////////////////
                             GAS REFUND
    //////////////////////////////////////////////////////////////*/

    function test_revertWhen_gasTokenNotWhitelisted() public {
        Execution[] memory calls = _justRouter();
        bytes32 h = _digest(intentExecutor, account, NONCE, calls, _gasRefundHash(otherToken, 1, true));
        bytes memory data = _blobWithGasRefund(account, NONCE, otherToken, 1, calls);
        vm.expectRevert(
            abi.encodeWithSelector(
                IBaseIntentExecutorPolicy.GasTokenNotWhitelisted.selector, otherToken
            )
        );
        policy.check1271SignedAction(configId, address(0), account, h, data);
    }

    function testFuzz_revertWhen_exchangeRateAboveCap(uint256 rate) public {
        vm.assume(rate > MAX_EX_RATE);
        Execution[] memory calls = _justRouter();
        bytes32 h = _digest(intentExecutor, account, NONCE, calls, _gasRefundHash(token, rate, true));
        bytes memory data = _blobWithGasRefund(account, NONCE, token, rate, calls);
        vm.expectRevert(
            abi.encodeWithSelector(IBaseIntentExecutorPolicy.ExchangeRateOverCap.selector, rate, MAX_EX_RATE)
        );
        policy.check1271SignedAction(configId, address(0), account, h, data);
    }

    /*//////////////////////////////////////////////////////////////
                                ACL
    //////////////////////////////////////////////////////////////*/

    function testFuzz_revertWhen_approveSpenderNotRouter(address spender) public {
        vm.assume(spender != relayRouter);
        Execution[] memory calls = new Execution[](1);
        calls[0] = _erc20Approve(token, spender, 1);
        (bytes32 h, bytes memory data) = _build(calls, address(0), 0);
        vm.expectRevert(
            abi.encodeWithSelector(RelayAdapter.RelayApproveBadSpender.selector, uint256(0))
        );
        policy.check1271SignedAction(configId, address(0), account, h, data);
    }

    function testFuzz_revertWhen_transferRecipientNotWhitelisted(address dest) public {
        vm.assume(dest != recipient);
        Execution[] memory calls = new Execution[](1);
        calls[0] = _erc20Transfer(token, dest, 1);
        (bytes32 h, bytes memory data) = _build(calls, address(0), 0);
        vm.expectRevert(
            abi.encodeWithSelector(RelayAdapter.RelayTransferBadRecipient.selector, uint256(0))
        );
        policy.check1271SignedAction(configId, address(0), account, h, data);
    }

    function testFuzz_revertWhen_targetIsRandom(address target) public {
        vm.assume(target != relayRouter && target != ieAdapter && target != token);
        Execution[] memory calls = new Execution[](1);
        calls[0] = Execution({ target: target, value: 0, callData: hex"" });
        (bytes32 h, bytes memory data) = _build(calls, address(0), 0);
        vm.expectRevert(abi.encodeWithSelector(RelayAdapter.RelayTargetDeny.selector, uint256(0)));
        policy.check1271SignedAction(configId, address(0), account, h, data);
    }

    function testFuzz_revertWhen_routerSelectorWrong(bytes4 sel) public {
        vm.assume(
            sel != RelayCalldataLib.SEL_RELAY_MULTICALL
                && sel != RelayCalldataLib.SEL_RELAY_TRANSFER_AND_MULTICALL
        );
        Execution[] memory calls = new Execution[](1);
        calls[0] = Execution({ target: relayRouter, value: 0, callData: abi.encodeWithSelector(sel) });
        (bytes32 h, bytes memory data) = _build(calls, address(0), 0);
        vm.expectRevert(
            abi.encodeWithSelector(RelayAdapter.RelayRouterBadSelector.selector, uint256(0))
        );
        policy.check1271SignedAction(configId, address(0), account, h, data);
    }

    function test_revertWhen_tokenCallWithEthValue() public {
        Execution[] memory calls = new Execution[](1);
        calls[0] = Execution({
            target: token,
            value: 1,
            callData: abi.encodeWithSelector(RelayCalldataLib.SEL_ERC20_APPROVE, relayRouter, 1)
        });
        (bytes32 h, bytes memory data) = _build(calls, address(0), 0);
        vm.expectRevert(
            abi.encodeWithSelector(RelayAdapter.RelayTokenValueNonzero.selector, uint256(0))
        );
        policy.check1271SignedAction(configId, address(0), account, h, data);
    }

    function test_revertWhen_adapterCallWithEthValue() public {
        Execution[] memory calls = new Execution[](1);
        calls[0] = Execution({ target: ieAdapter, value: 1, callData: hex"deadbeef" });
        (bytes32 h, bytes memory data) = _build(calls, address(0), 0);
        vm.expectRevert(
            abi.encodeWithSelector(RelayAdapter.RelayAdapterValueNonzero.selector, uint256(0))
        );
        policy.check1271SignedAction(configId, address(0), account, h, data);
    }

    /*//////////////////////////////////////////////////////////////
                              OPS BOUNDS
    //////////////////////////////////////////////////////////////*/

    function test_acceptsExactlyMaxOps() public view {
        Execution[] memory calls = new Execution[](16);
        for (uint256 i; i < 16; i++) {
            calls[i] = _routerCall(RelayCalldataLib.SEL_RELAY_MULTICALL, 0);
        }
        (bytes32 h, bytes memory data) = _build(calls, address(0), 0);
        assertTrue(policy.check1271SignedAction(configId, address(0), account, h, data));
    }

    function test_revertWhen_opsCountIsSeventeen() public {
        Execution[] memory calls = new Execution[](17);
        for (uint256 i; i < 17; i++) {
            calls[i] = _routerCall(RelayCalldataLib.SEL_RELAY_MULTICALL, 0);
        }
        (bytes32 h, bytes memory data) = _build(calls, address(0), 0);
        vm.expectRevert(
            abi.encodeWithSelector(OpsCalldataLib.OpsCountExceeded.selector, uint256(17), uint256(16))
        );
        policy.check1271SignedAction(configId, address(0), account, h, data);
    }

    /*//////////////////////////////////////////////////////////////
                            MALFORMED DATA
    //////////////////////////////////////////////////////////////*/

    function test_revertWhen_approveCalldataWrongLength() public {
        Execution[] memory calls = new Execution[](1);
        calls[0] = Execution({
            target: token,
            value: 0,
            callData: abi.encodePacked(
                RelayCalldataLib.SEL_ERC20_APPROVE, bytes32(uint256(uint160(relayRouter)))
            )
        });
        (bytes32 h, bytes memory data) = _build(calls, address(0), 0);
        vm.expectRevert(RelayCalldataLib.MalformedCall.selector);
        policy.check1271SignedAction(configId, address(0), account, h, data);
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    function _build(
        Execution[] memory calls,
        address gasToken,
        uint256 exchangeRate
    )
        internal
        view
        returns (bytes32 h, bytes memory data)
    {
        bool present = gasToken != address(0) || exchangeRate != 0;
        h = _digest(intentExecutor, account, NONCE, calls, _gasRefundHash(gasToken, exchangeRate, present));
        if (present) {
            data = _blobWithGasRefund(account, NONCE, gasToken, exchangeRate, calls);
        } else {
            data = _blobSansGasRefund(account, NONCE, calls);
        }
    }

    function _justRouter() internal view returns (Execution[] memory calls) {
        calls = new Execution[](1);
        calls[0] = _routerCall(RelayCalldataLib.SEL_RELAY_MULTICALL, 0);
    }

    function _routerCall(bytes4 sel, uint256 value) internal view returns (Execution memory) {
        return Execution({ target: relayRouter, value: value, callData: abi.encodeWithSelector(sel) });
    }

    function _erc20Approve(
        address tkn,
        address spender,
        uint256 amount
    )
        internal
        pure
        returns (Execution memory)
    {
        return Execution({
            target: tkn,
            value: 0,
            callData: abi.encodeWithSelector(RelayCalldataLib.SEL_ERC20_APPROVE, spender, amount)
        });
    }

    function _erc20Transfer(
        address tkn,
        address to,
        uint256 amount
    )
        internal
        pure
        returns (Execution memory)
    {
        return Execution({
            target: tkn,
            value: 0,
            callData: abi.encodeWithSelector(RelayCalldataLib.SEL_ERC20_TRANSFER, to, amount)
        });
    }
}
