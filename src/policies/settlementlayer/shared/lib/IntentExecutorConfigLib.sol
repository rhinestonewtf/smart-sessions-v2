// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

import { EnumerableSetLib } from "solady/utils/EnumerableSetLib.sol";

import {
    IntentExecutorStorage
} from "@policies/settlementlayer/shared/lib/IntentExecutorStorageLib.sol";

/// @title IntentExecutorConfigLib
/// @notice Decodes the packed init blob for the base IntentExecutor policy.
/// @dev Layout (packed, in order):
///        [0:20]  intentExecutor address
///        [20]    flags (uint8)
///        [21:53] maxExchangeRate (uint256)
///        [53]    gasTokenCount (uint8)
///        [54:..] gasTokens (20 bytes each)
///        [..]    subclass-init blob (returned as `remaining`)
library IntentExecutorConfigLib {
    using EnumerableSetLib for EnumerableSetLib.AddressSet;

    error ConfigAlreadyInitialized();
    error InvalidConfigData();

    uint256 private constant HEADER_LEN = 54;

    /// @notice Decodes the header and populates `$`, returning the unconsumed tail for the
    ///         subclass to parse its own configuration.
    function initializeBase(
        IntentExecutorStorage storage $,
        address account,
        bytes calldata initData
    )
        internal
        returns (bytes calldata remaining)
    {
        if ($.intentExecutor != address(0)) revert ConfigAlreadyInitialized();
        if (initData.length < HEADER_LEN) revert InvalidConfigData();

        address ie = address(bytes20(initData[0:20]));
        if (ie == address(0)) revert InvalidConfigData();
        $.intentExecutor = ie;

        uint8 flags = uint8(initData[20]);
        $.flags = flags;
        $.maxExchangeRate = uint256(bytes32(initData[21:53]));

        // Pin the account when FLAG_LOCK_ACCOUNT is set. Otherwise leave zero so the policy
        // accepts any caller that smartSessions has approved for this configId.
        // The flag is the low bit (bit 1) of the flags byte; see IntentExecutorDataTypes.
        if ((flags & 0x02) != 0) $.pinnedAccount = account;

        uint8 tokenCount = uint8(initData[53]);
        uint256 cursor = HEADER_LEN;
        uint256 end = cursor + uint256(tokenCount) * 20;
        if (initData.length < end) revert InvalidConfigData();
        for (uint256 i; i < tokenCount; i++) {
            address token = address(bytes20(initData[cursor:cursor + 20]));
            // Duplicates silently collapse via the set; zero-address is a sentinel callers
            // should not use as a gas token and we reject it explicitly.
            if (token == address(0)) revert InvalidConfigData();
            $.gasTokenWhitelist.add(token);
            cursor += 20;
        }

        remaining = initData[cursor:];
    }
}
