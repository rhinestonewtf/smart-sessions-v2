// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

import { EIP712Lib } from "@compact-utils/executor/StandaloneIntent/lib/EIP712Lib.sol";
import { EIP712TypeHashLib } from "@compact-utils/types/EIP712TypeHashLib.sol";
import { Types } from "@compact-utils/types/OrderTypes.sol";

import {
    EIP712_DOMAIN_TYPEHASH,
    INTENT_EXECUTOR_NAME_HASH,
    INTENT_EXECUTOR_VERSION_HASH,
    NO_GASREFUND
} from "@policies/settlementlayer/shared/types/IntentExecutorDataTypes.sol";

/// @title IntentExecutorEIP712Lib
/// @notice Recomputes the EIP-712 digest a smart account would have ERC-1271-signed when
///         authorising a `StandaloneIntentExecutor.executeSinglechainOps` (and, in a follow-up,
///         `executeMultichainOps`) call.
/// @dev The struct-hash builders delegate to `EIP712Lib` and `EIP712TypeHashLib` from
///      `@compact-utils` so the on-chain typehashes stay in lock-step with the deployed
///      executor. We only own the domain-separator side, which the executor builds via
///      `solady/EIP712` with the constants from `IntentExecutorDataTypes.sol`.
library IntentExecutorEIP712Lib {
    using EIP712TypeHashLib for Types.Operation;

    /// @notice Builds the EIP-712 domain separator for a given executor address.
    /// @dev Matches `solady/EIP712._buildDomainSeparator()` using the constants for the
    ///      `IntentExecutor` domain: `name = "IntentExecutor"`, `version = "v0.0.1"`.
    function domainSeparator(address verifyingContract)
        internal
        view
        returns (bytes32 separator)
    {
        bytes32 nameHash = INTENT_EXECUTOR_NAME_HASH;
        bytes32 versionHash = INTENT_EXECUTOR_VERSION_HASH;
        bytes32 typeHash = EIP712_DOMAIN_TYPEHASH;
        // solhint-disable-next-line no-inline-assembly
        assembly ("memory-safe") {
            let m := mload(0x40)
            mstore(m, typeHash)
            mstore(add(m, 0x20), nameHash)
            mstore(add(m, 0x40), versionHash)
            mstore(add(m, 0x60), chainid())
            mstore(add(m, 0x80), verifyingContract)
            separator := keccak256(m, 0xa0)
        }
    }

    /// @notice Wraps a struct hash with the IntentExecutor domain separator.
    /// @dev `keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash))` — the
    ///      canonical EIP-712 typed-data digest.
    function hashTypedData(
        address verifyingContract,
        bytes32 structHash
    )
        internal
        view
        returns (bytes32 digest)
    {
        bytes32 sep = domainSeparator(verifyingContract);
        // solhint-disable-next-line no-inline-assembly
        assembly ("memory-safe") {
            mstore(0x00, 0x1901000000000000000000000000000000000000000000000000000000000000)
            mstore(0x02, sep)
            mstore(0x22, structHash)
            digest := keccak256(0x00, 0x42)
            mstore(0x22, 0) // restore zero slot
        }
    }

    /// @notice Builds the `SingleChainOps` struct hash that goes into the EIP-712 digest.
    /// @param account     Account in the SingleChainOps struct.
    /// @param nonce       Nonce in the SingleChainOps struct.
    /// @param ops         `Operation` calldata pointer; passed through to the executor's
    ///                    own hashing logic so the typehash and exec-type dispatch stay
    ///                    identical.
    /// @param gasRefundHash Pre-computed `GasRefund` struct hash, or `NO_GASREFUND`.
    function structHashSingleChainOps(
        address account,
        uint256 nonce,
        Types.Operation calldata ops,
        bytes32 gasRefundHash
    )
        internal
        pure
        returns (bytes32)
    {
        return EIP712Lib.hashSingleChainOps(account, nonce, ops, gasRefundHash);
    }

    /// @notice `keccak256(GasRefund(token, exchangeRate))` matching `EIP712Lib.hashGasRefund`.
    function hashGasRefund(
        address token,
        uint256 exchangeRate
    )
        internal
        pure
        returns (bytes32)
    {
        return EIP712Lib.hashGasRefund(token, exchangeRate);
    }

    /// @dev Re-exported for callers that want to compare against the no-gas-refund constant
    ///      without importing the data-types file directly.
    function noGasRefund() internal pure returns (bytes32) {
        return NO_GASREFUND;
    }
}
