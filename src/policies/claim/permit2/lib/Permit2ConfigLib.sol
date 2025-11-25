// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Types
import { Permit2TokenInStorageConfig } from "@policies/claim/permit2/types/Permit2DataTypes.sol";

// forgefmt: disable-start
/// @title Permit2 Config Library
/// @author Rhinestone
/// @notice Decoding utilities for Permit2-specific configuration
///
/// ┌────────────────────────────────────────────────────────────┐
/// │              Permit2 TokenIn Config Layout                 │
/// │                                                            │
/// │  ┌──────────────────────────────────────────────────────┐  │
/// │  │  count (32 bytes)                                    │  │
/// │  │  Entry[]:                                            │  │
/// │  │    - chainId (32 bytes)                              │  │
/// │  │    - token (20 bytes)                                │  │
/// │  └──────────────────────────────────────────────────────┘  │
/// │                                                            │
/// │  Total per entry: 52 bytes                                 │
/// └────────────────────────────────────────────────────────────┘
// forgefmt: disable-end
library Permit2ConfigLib {
    /*//////////////////////////////////////////////////////////////
                           TOKEN IN CONFIG
    //////////////////////////////////////////////////////////////*/

    /// @notice Decodes Permit2TokenInStorageConfig array from init data
    /// @dev Token-only format (no lockTag)
    /// @param initData The initialization calldata
    /// @return configs Array of decoded token configs
    /// @return remaining Remaining calldata after decoding
    /// @return bytesConsumed Number of bytes consumed
    function decodeTokenInConfig(bytes calldata initData)
        internal
        pure
        returns (
            Permit2TokenInStorageConfig[] memory configs,
            bytes calldata remaining,
            uint256 bytesConsumed
        )
    {
        // Read count
        uint256 count = uint256(bytes32(initData[0:32]));
        configs = new Permit2TokenInStorageConfig[](count);

        uint256 offset = 32;

        // Decode each entry: [chainId (32) | token (20)]
        for (uint256 i = 0; i < count; i++) {
            configs[i].chainId = uint256(bytes32(initData[offset:offset + 32]));
            offset += 32;

            configs[i].token = address(bytes20(initData[offset:offset + 20]));
            offset += 20;
        }

        bytesConsumed = offset;
        remaining = initData[offset:];
    }
}
