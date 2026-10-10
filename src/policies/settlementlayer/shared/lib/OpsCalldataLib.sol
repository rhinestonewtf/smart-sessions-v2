// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

import { Execution } from "modulekit/integrations/ERC7579Exec.sol";
import { SmartExecutionLib } from "@compact-utils/common/SmartExecutionLib.sol";
import { Types } from "@compact-utils/types/OrderTypes.sol";

import { MAX_OPS } from "@policies/settlementlayer/shared/types/IntentExecutorDataTypes.sol";

/// @title OpsCalldataLib
/// @notice Bounded calldata walker for the `Execution[]` payload embedded in a signed
///         `Types.Operation`.
/// @dev v1 supports only `Type.ERC7579` execution data — same shape the orchestrator emits
///      via `encodeExecutions` (see `compact/adapters/implementations/intentExecutor.ts`).
///      Other execution types (`MultiCall`, `Calldata`, `Eip712Hash`) are out of scope and
///      callers must reject them before invoking this lib.
library OpsCalldataLib {
    using SmartExecutionLib for Types.Operation;

    error OpsCountExceeded(uint256 count, uint256 max);
    error UnsupportedExecutionType();

    /// @notice Resolves the ERC-7579 execution array embedded in `ops`.
    /// @dev Reverts if the exec type isn't `ERC7579` or if there are more than `MAX_OPS` calls.
    function executions(Types.Operation calldata ops)
        internal
        pure
        returns (Execution[] calldata calls)
    {
        SmartExecutionLib.Type execType = ops.toExecType();
        if (execType != SmartExecutionLib.Type.ERC7579) revert UnsupportedExecutionType();
        calls = ops.safeToERC7579();
        uint256 n = calls.length;
        if (n > MAX_OPS) revert OpsCountExceeded(n, MAX_OPS);
    }

    /// @notice Returns the selector at the head of an inner call's `data`.
    /// @dev Returns the zero selector for calls with fewer than 4 bytes of payload
    ///      (callers typically treat this as "value transfer / native send").
    function selectorOf(bytes calldata data) internal pure returns (bytes4 sel) {
        if (data.length < 4) return bytes4(0);
        return bytes4(data[:4]);
    }
}
