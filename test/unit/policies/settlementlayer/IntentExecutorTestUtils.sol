// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { Execution } from "modulekit/integrations/ERC7579Exec.sol";
import { Types } from "@compact-utils/types/OrderTypes.sol";

import {
    IntentExecutorEIP712Lib
} from "@policies/settlementlayer/shared/lib/IntentExecutorEIP712Lib.sol";
import {
    VARIANT_SINGLE_CHAIN,
    NO_GASREFUND
} from "@policies/settlementlayer/shared/types/IntentExecutorDataTypes.sol";

/// @title IntentExecutorTestUtils
/// @notice Shared helpers for the IntentExecutor policy test suites.
/// @dev Builds the (digest, data-blob) pair that smart-sessions would hand to
///      `check1271SignedAction` when the smart account is asked to ERC-1271-sign a
///      `StandaloneIntentExecutor.executeSinglechainOps` digest. The helpers are split
///      across an internal "build the EIP-712 view of the Operation" path and a "build
///      the packed data blob" path so adversarial tests can mutate one without the
///      other (e.g. recompute the digest but feed a tampered blob).
contract IntentExecutorTestUtils {
    /// @dev Builds the inner `Operation.data` from a list of ERC-7579 executions.
    ///      `vt` byte 0 = `Type.ERC7579` (= 3), byte 1 = signature mode (irrelevant for
    ///      hashing). The rest of `data` is `abi.encode(Execution[])`.
    function _opData(Execution[] memory calls) internal pure returns (bytes memory) {
        return bytes.concat(bytes2(0x0300), abi.encode(calls));
    }

    /// @dev Wraps the `opData` produced above into a packed `Operation` blob suitable for
    ///      appending to the policy data argument. ABI encoding is `(bytes)`, which is
    ///      what the base policy's `_decodeOperation` casts at.
    function _opBlob(Execution[] memory calls) internal pure returns (bytes memory) {
        return abi.encode(Types.Operation({ data: _opData(calls) }));
    }

    /// @dev Computes the policy-side EIP-712 digest the smart account would have signed.
    ///      Splits the building so callers can mutate the blob after computing the
    ///      "correct" digest (used in digest-mismatch tests).
    function _digest(
        address intentExecutor,
        address account,
        uint256 nonce,
        Execution[] memory calls,
        bytes32 gasRefundHash
    )
        internal
        view
        returns (bytes32 hash)
    {
        Types.Operation memory opMem = Types.Operation({ data: _opData(calls) });
        bytes32 structHash =
            IntentExecutorTestUtils(address(this))._structHash(account, nonce, opMem, gasRefundHash);
        hash = IntentExecutorEIP712Lib.hashTypedData(intentExecutor, structHash);
    }

    /// @dev External wrapper so we can hand a calldata `Operation` pointer to the lib
    ///      (which only accepts `calldata`).
    function _structHash(
        address account,
        uint256 nonce,
        Types.Operation calldata ops,
        bytes32 gasRefundHash
    )
        external
        pure
        returns (bytes32)
    {
        return IntentExecutorEIP712Lib.structHashSingleChainOps(account, nonce, ops, gasRefundHash);
    }

    /// @dev Packs a SingleChain data blob without gas refund.
    function _blobSansGasRefund(
        address account,
        uint256 nonce,
        Execution[] memory calls
    )
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            uint8(VARIANT_SINGLE_CHAIN),
            uint8(0),
            account,
            nonce,
            _opBlob(calls)
        );
    }

    /// @dev Packs a SingleChain data blob *with* gas refund (non-zero typehash).
    function _blobWithGasRefund(
        address account,
        uint256 nonce,
        address gasToken,
        uint256 exchangeRate,
        Execution[] memory calls
    )
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            uint8(VARIANT_SINGLE_CHAIN),
            uint8(1),
            account,
            nonce,
            gasToken,
            exchangeRate,
            _opBlob(calls)
        );
    }

    /// @dev Returns the EIP-712 GasRefund hash for the supplied (token, rate); falls back
    ///      to `NO_GASREFUND` when the policy data flagged `hasGasRefund == 0`.
    function _gasRefundHash(
        address token,
        uint256 rate,
        bool present
    )
        internal
        pure
        returns (bytes32)
    {
        if (!present) return NO_GASREFUND;
        return IntentExecutorEIP712Lib.hashGasRefund(token, rate);
    }
}
