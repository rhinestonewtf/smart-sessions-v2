// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

import { Execution } from "modulekit/integrations/ERC7579Exec.sol";

import {
    IIntentExecutorAdapter
} from "@policies/settlementlayer/shared/interfaces/IIntentExecutorAdapter.sol";
import { OpsCalldataLib } from "@policies/settlementlayer/shared/lib/OpsCalldataLib.sol";
import { CCTPCalldataLib } from "@policies/settlementlayer/shared/lib/CCTPCalldataLib.sol";

/// @title CCTPAdapter
/// @notice Stateless Circle CCTP V2 validator.
///
/// @dev   Config blob layout (packed):
///        ┌────────────────────────────────────────────────────────────────┐
///        │  [0:20]    tokenMessenger                                      │
///        │  [20:52]   maxFeeCap (uint256, 0 = no cap)                     │
///        │  [52:56]   minFinalityFloor (uint32)                           │
///        │  [56]      mintRecipientCount (uint8)                          │
///        │  [...]     mintRecipients (32 bytes each)                      │
///        │  [...]     burnTokenCount (uint8)                              │
///        │  [...]     burnTokens (20 bytes each)                          │
///        │  [...]     destDomainCount (uint8); 0 = any domain             │
///        │  [...]     destDomains (4 bytes each)                          │
///        └────────────────────────────────────────────────────────────────┘
contract CCTPAdapter is IIntentExecutorAdapter {
    bytes32 public constant LAYER_ID = keccak256("CCTP");

    error CCTPMessengerBadSelector(uint256 callIndex);
    error CCTPTokenBadSelector(uint256 callIndex);
    error CCTPApproveBadSpender(uint256 callIndex);
    error CCTPMintRecipientDeny(uint256 callIndex, bytes32 mintRecipient);
    error CCTPBurnTokenDeny(uint256 callIndex, address burnToken);
    error CCTPDestDomainDeny(uint256 callIndex, uint32 destDomain);
    error CCTPMaxFeeOverCap(uint256 callIndex, uint256 maxFee, uint256 cap);
    error CCTPMinFinalityLow(uint256 callIndex, uint32 provided, uint32 floor);
    error CCTPValueNonzero(uint256 callIndex);
    error CCTPTargetDeny(uint256 callIndex);
    error CCTPInvalidConfig();

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
        Layout memory L = _scan(config);
        address to = call.target;
        bytes calldata data = call.callData;
        bytes4 sel = OpsCalldataLib.selectorOf(data);

        if (call.value != 0) revert CCTPValueNonzero(callIndex);

        if (to == L.tokenMessenger) {
            if (sel != CCTPCalldataLib.SEL_DEPOSIT_FOR_BURN_WITH_HOOK) {
                revert CCTPMessengerBadSelector(callIndex);
            }
            (
                ,
                uint32 dom,
                bytes32 mintRecipient,
                address burnToken,,
                uint256 maxFee,
                uint32 minFinality
            ) = CCTPCalldataLib.decodeDepositForBurnWithHook(data);

            if (!_containsBytes32(config, L.mintStart, L.mintLen, mintRecipient)) {
                revert CCTPMintRecipientDeny(callIndex, mintRecipient);
            }
            if (!_containsAddress(config, L.burnStart, L.burnLen, burnToken)) {
                revert CCTPBurnTokenDeny(callIndex, burnToken);
            }
            if (L.domLen != 0 && !_containsUint32(config, L.domStart, L.domLen, dom)) {
                revert CCTPDestDomainDeny(callIndex, dom);
            }
            if (L.maxFeeCap != 0 && maxFee > L.maxFeeCap) {
                revert CCTPMaxFeeOverCap(callIndex, maxFee, L.maxFeeCap);
            }
            if (minFinality < L.minFinalityFloor) {
                revert CCTPMinFinalityLow(callIndex, minFinality, L.minFinalityFloor);
            }
            return;
        }

        if (_containsAddress(config, L.burnStart, L.burnLen, to)) {
            if (sel != CCTPCalldataLib.SEL_ERC20_APPROVE) revert CCTPTokenBadSelector(callIndex);
            (address spender,) = CCTPCalldataLib.decodeApprove(data);
            if (spender != L.tokenMessenger) revert CCTPApproveBadSpender(callIndex);
            return;
        }

        revert CCTPTargetDeny(callIndex);
    }

    struct Layout {
        address tokenMessenger;
        uint256 maxFeeCap;
        uint32 minFinalityFloor;
        uint256 mintStart;
        uint256 mintLen;
        uint256 burnStart;
        uint256 burnLen;
        uint256 domStart;
        uint256 domLen;
    }

    function _scan(bytes calldata config) private pure returns (Layout memory L) {
        if (config.length < 57) revert CCTPInvalidConfig();
        L.tokenMessenger = address(bytes20(config[0:20]));
        L.maxFeeCap = uint256(bytes32(config[20:52]));
        L.minFinalityFloor = uint32(bytes4(config[52:56]));
        uint8 mc = uint8(config[56]);
        L.mintStart = 57;
        L.mintLen = uint256(mc);
        uint256 cursor = L.mintStart + 32 * uint256(mc);
        if (config.length < cursor + 1) revert CCTPInvalidConfig();
        uint8 bc = uint8(config[cursor]);
        cursor += 1;
        L.burnStart = cursor;
        L.burnLen = uint256(bc);
        cursor += 20 * uint256(bc);
        if (config.length < cursor + 1) revert CCTPInvalidConfig();
        uint8 dc = uint8(config[cursor]);
        cursor += 1;
        L.domStart = cursor;
        L.domLen = uint256(dc);
        cursor += 4 * uint256(dc);
        if (config.length != cursor) revert CCTPInvalidConfig();
    }

    function _containsBytes32(
        bytes calldata config,
        uint256 start,
        uint256 len,
        bytes32 target
    )
        private
        pure
        returns (bool)
    {
        for (uint256 i; i < len; i++) {
            if (bytes32(config[start + 32 * i:start + 32 * i + 32]) == target) return true;
        }
        return false;
    }

    function _containsAddress(
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

    function _containsUint32(
        bytes calldata config,
        uint256 start,
        uint256 len,
        uint32 target
    )
        private
        pure
        returns (bool)
    {
        for (uint256 i; i < len; i++) {
            if (uint32(bytes4(config[start + 4 * i:start + 4 * i + 4])) == target) return true;
        }
        return false;
    }
}
