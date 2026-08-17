// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

import { Execution } from "modulekit/integrations/ERC7579Exec.sol";

import {
    IIntentExecutorAdapter
} from "@policies/settlementlayer/shared/interfaces/IIntentExecutorAdapter.sol";
import { OpsCalldataLib } from "@policies/settlementlayer/shared/lib/OpsCalldataLib.sol";
import { RelayCalldataLib } from "@policies/settlementlayer/shared/lib/RelayCalldataLib.sol";

/// @title RelayAdapter
/// @notice Stateless Relay validator. Used by both `StaticIntentExecutorPolicy`
///         (hard-wired to one adapter at construction) and `OwnableIntentExecutorPolicy`
///         (registry-managed). All ACL logic lives here so the two policies share it
///         verbatim.
///
/// @dev   Config blob layout (calldata-friendly, packed):
///        ┌────────────────────────────────────────────────────────────────┐
///        │  [0:20]    relayRouter                                         │
///        │  [20:40]   intentExecutorAdapter (zero = adapter calls denied) │
///        │  [40]      recipientCount (uint8)                              │
///        │  [...]     recipients (20 bytes each)                          │
///        │  [...]     tokenCount (uint8)                                  │
///        │  [...]     tokens (20 bytes each)                              │
///        └────────────────────────────────────────────────────────────────┘
contract RelayAdapter is IIntentExecutorAdapter {
    bytes32 public constant LAYER_ID = keccak256("RELAY");

    /// @dev All revert paths carry the inner-call index so the caller can pinpoint which
    ///      Operation.ops[i] was rejected.
    error RelayRouterBadSelector(uint256 callIndex);
    error RelayApproveBadSpender(uint256 callIndex);
    error RelayTransferBadRecipient(uint256 callIndex);
    error RelayTokenBadSelector(uint256 callIndex);
    error RelayTokenValueNonzero(uint256 callIndex);
    error RelayAdapterValueNonzero(uint256 callIndex);
    error RelayTargetDeny(uint256 callIndex);
    error RelayInvalidConfig();

    function layerId() external pure override returns (bytes32) {
        return LAYER_ID;
    }

    function validateConfig(bytes calldata config) external pure override {
        _scan(config);
    }

    function validateCall(
        bytes32, /* configHash */
        bytes calldata config,
        uint256 callIndex,
        Execution calldata call
    )
        external
        pure
        override
    {
        (
            address relayRouter,
            address ieAdapter,
            uint256 recipientsStart,
            uint256 recipientsLen,
            uint256 tokensStart,
            uint256 tokensLen
        ) = _scan(config);

        address to = call.target;
        uint256 value = call.value;
        bytes calldata data = call.callData;
        bytes4 sel = OpsCalldataLib.selectorOf(data);

        if (to == relayRouter) {
            // ETH may flow through the router for swaps.
            if (
                sel == RelayCalldataLib.SEL_RELAY_MULTICALL
                    || sel == RelayCalldataLib.SEL_RELAY_TRANSFER_AND_MULTICALL
            ) return;
            revert RelayRouterBadSelector(callIndex);
        }

        if (ieAdapter != address(0) && to == ieAdapter) {
            if (value != 0) revert RelayAdapterValueNonzero(callIndex);
            return;
        }

        if (_contains(config, tokensStart, tokensLen, to)) {
            if (value != 0) revert RelayTokenValueNonzero(callIndex);
            if (sel == RelayCalldataLib.SEL_ERC20_APPROVE) {
                (address spender,) = RelayCalldataLib.decodeApprove(data);
                if (spender != relayRouter) revert RelayApproveBadSpender(callIndex);
                return;
            }
            if (sel == RelayCalldataLib.SEL_ERC20_TRANSFER) {
                (address rec,) = RelayCalldataLib.decodeTransfer(data);
                if (!_contains(config, recipientsStart, recipientsLen, rec)) {
                    revert RelayTransferBadRecipient(callIndex);
                }
                return;
            }
            revert RelayTokenBadSelector(callIndex);
        }

        revert RelayTargetDeny(callIndex);
    }

    function _scan(bytes calldata config)
        private
        pure
        returns (
            address relayRouter,
            address ieAdapter,
            uint256 recipientsStart,
            uint256 recipientsLen,
            uint256 tokensStart,
            uint256 tokensLen
        )
    {
        if (config.length < 41) revert RelayInvalidConfig();
        relayRouter = address(bytes20(config[0:20]));
        ieAdapter = address(bytes20(config[20:40]));
        uint8 rc = uint8(config[40]);
        recipientsStart = 41;
        recipientsLen = uint256(rc);
        uint256 tcOff = 41 + 20 * uint256(rc);
        if (config.length < tcOff + 1) revert RelayInvalidConfig();
        uint8 tc = uint8(config[tcOff]);
        tokensStart = tcOff + 1;
        tokensLen = uint256(tc);
        if (config.length != tokensStart + 20 * uint256(tc)) revert RelayInvalidConfig();
    }

    function _contains(
        bytes calldata config,
        uint256 start,
        uint256 len,
        address target
    )
        private
        pure
        returns (bool)
    {
        for (uint256 i; i < len; i++) {
            if (address(bytes20(config[start + 20 * i:start + 20 * i + 20])) == target) {
                return true;
            }
        }
        return false;
    }
}
