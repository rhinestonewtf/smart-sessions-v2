// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

// Libraries
import { HashLibV2 } from "@lib/HashLibV2.sol";

// Types
import { EnableSession } from "@types/DataTypes.sol";
import { ChainDigest } from "@smartsessions/DataTypes.sol";

/// @title HashLibV2Simulate
/// @notice Simulation variant of HashLibV2 for gas estimation.
/// @dev Identical to HashLibV2.getAndVerifyDigest for EnableSession but omits the
///      HashMismatch revert so the orchestrator can simulate without a real user
///      signature. ChainId check is preserved.
library HashLibV2Simulate {
    using HashLibV2 for *;

    error ChainIdMismatch(uint64 providedChainId);

    /// @notice Computes the multichain digest without reverting on hash mismatch.
    /// @dev Drop-in replacement for HashLibV2.getAndVerifyDigest(EnableSession,...).
    ///      Only difference: HashMismatch revert is omitted.
    function getAndVerifyDigest(
        EnableSession memory enableData,
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
