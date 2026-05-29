// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

import { Execution } from "modulekit/integrations/ERC7579Exec.sol";

import {
    IIntentExecutorAdapter
} from "@policies/settlementlayer/shared/interfaces/IIntentExecutorAdapter.sol";
import { OpsCalldataLib } from "@policies/settlementlayer/shared/lib/OpsCalldataLib.sol";
import { RhinoCalldataLib } from "@policies/settlementlayer/shared/lib/RhinoCalldataLib.sol";

/// @title RhinoAdapter
/// @notice Stateless Rhino.fi (DVFDepositContract) validator.
///
/// @dev   Config blob layout (packed):
///        ┌────────────────────────────────────────────────────────────────┐
///        │  [0:20]   bridgeContract                                       │
///        │  [20]     tokenCount (uint8)                                   │
///        │  [...]    tokens (20 bytes each)                               │
///        └────────────────────────────────────────────────────────────────┘
contract RhinoAdapter is IIntentExecutorAdapter {
    bytes32 public constant LAYER_ID = keccak256("RHINO");

    error RhinoBridgeBadSelector(uint256 callIndex);
    error RhinoTokenBadSelector(uint256 callIndex);
    error RhinoApproveBadSpender(uint256 callIndex);
    error RhinoDepositTokenDeny(uint256 callIndex, address token);
    error RhinoValueNonzero(uint256 callIndex);
    error RhinoTargetDeny(uint256 callIndex);
    error RhinoInvalidConfig();

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
        (address bridge, uint256 tokensStart, uint256 tokensLen) = _scan(config);
        address to = call.target;
        bytes calldata data = call.callData;
        bytes4 sel = OpsCalldataLib.selectorOf(data);

        if (call.value != 0) revert RhinoValueNonzero(callIndex);

        if (to == bridge) {
            if (sel != RhinoCalldataLib.SEL_DEPOSIT_WITH_ID) revert RhinoBridgeBadSelector(callIndex);
            (address token,,) = RhinoCalldataLib.decodeDepositWithId(data);
            if (!_contains(config, tokensStart, tokensLen, token)) {
                revert RhinoDepositTokenDeny(callIndex, token);
            }
            return;
        }

        if (_contains(config, tokensStart, tokensLen, to)) {
            if (sel != RhinoCalldataLib.SEL_ERC20_APPROVE) revert RhinoTokenBadSelector(callIndex);
            (address spender,) = RhinoCalldataLib.decodeApprove(data);
            if (spender != bridge) revert RhinoApproveBadSpender(callIndex);
            return;
        }

        revert RhinoTargetDeny(callIndex);
    }

    function _scan(bytes calldata config)
        private
        pure
        returns (address bridge, uint256 tokensStart, uint256 tokensLen)
    {
        if (config.length < 21) revert RhinoInvalidConfig();
        bridge = address(bytes20(config[0:20]));
        uint8 tc = uint8(config[20]);
        tokensStart = 21;
        tokensLen = uint256(tc);
        if (config.length != 21 + 20 * uint256(tc)) revert RhinoInvalidConfig();
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
            if (address(bytes20(config[start + 20 * i:start + 20 * i + 20])) == target) return true;
        }
        return false;
    }
}
