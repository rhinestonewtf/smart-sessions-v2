// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

// Libraries
import { HashLibV2 } from "@lib/HashLibV2.sol";
import { HashLibV2Calldata } from "@lib/HashLibV2Calldata.sol";

// Types
import { EnableSession } from "@types/DataTypes.sol";
import { ChainDigest } from "@smartsessions/DataTypes.sol";

/// @title HashLibV2CalldataSimulate
/// @notice Simulation variant of HashLibV2Calldata for gas estimation.
/// @dev Identical to HashLibV2Calldata.getAndVerifyDigest for EnableSession but omits the
///      HashMismatch revert. ChainId check is preserved.
library HashLibV2CalldataSimulate {
    using HashLibV2Calldata for *;

    error ChainIdMismatch(uint64 providedChainId);

    /// @notice Computes the multichain digest without reverting on hash mismatch.
    /// @dev Drop-in replacement for HashLibV2Calldata.getAndVerifyDigest(EnableSession calldata,...).
    ///      Only difference: HashMismatch revert is omitted.
    function getAndVerifyDigest(
        EnableSession calldata enableData,
        address, /* account */
        uint256, /* nonce */
        uint256, /* expires */
        bytes12 /* lockTag */
    )
        internal
        view
        returns (bytes32 digest)
    {
        uint64 providedChainId =
            enableData.hashesAndChainIds[enableData.chainDigestIndex].chainId;

        if (providedChainId != uint64(block.chainid)) revert ChainIdMismatch(providedChainId);

        // HashMismatch revert intentionally omitted for simulation

        digest = enableData.hashesAndChainIds.multichainDigest();
    }
}
