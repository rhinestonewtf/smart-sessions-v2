// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

/// @title CCTPCalldataLib
/// @notice Selectors and inline parsers for the Circle CCTP V2 calls the orchestrator
///         emits inside an IntentExecutor `Operation.ops` (see
///         `planning/strategies/cctp/element.ts` in `rhinestonewtf/orchestrator`).
///
/// @dev    The relevant entrypoint is Circle's `TokenMessengerV2.depositForBurnWithHook`.
///         The only other inner call shape is a plain ERC-20 `approve` to the messenger.
library CCTPCalldataLib {
    error MalformedCall();

    /// @dev `IERC20.approve(address,uint256)`.
    bytes4 internal constant SEL_ERC20_APPROVE = 0x095ea7b3;

    /// @dev `TokenMessengerV2.depositForBurnWithHook(
    ///         uint256 amount, uint32 destinationDomain, bytes32 mintRecipient,
    ///         address burnToken, bytes32 destinationCaller, uint256 maxFee,
    ///         uint32 minFinalityThreshold, bytes hookData)`.
    bytes4 internal constant SEL_DEPOSIT_FOR_BURN_WITH_HOOK = 0x779b432d;

    /// @dev Static-arg portion of `depositForBurnWithHook` is 7 32-byte words plus the
    ///      bytes head offset; total static head length is 8 * 32 = 256 bytes before the
    ///      dynamic `hookData` tail.
    uint256 private constant DEPOSIT_FOR_BURN_STATIC_LEN = 4 + 32 * 8;

    /// @notice Decodes the static arguments of `depositForBurnWithHook` without copying.
    /// @dev The caller is expected to have already matched the selector. The function
    ///      tolerates trailing bytes (the dynamic `hookData` tail) and does not validate
    ///      that the bytes-offset is well-formed beyond the static-head bound.
    function decodeDepositForBurnWithHook(bytes calldata data)
        internal
        pure
        returns (
            uint256 amount,
            uint32 destinationDomain,
            bytes32 mintRecipient,
            address burnToken,
            bytes32 destinationCaller,
            uint256 maxFee,
            uint32 minFinalityThreshold
        )
    {
        if (data.length < DEPOSIT_FOR_BURN_STATIC_LEN) revert MalformedCall();
        amount = uint256(bytes32(data[4:36]));
        destinationDomain = uint32(uint256(bytes32(data[36:68])));
        mintRecipient = bytes32(data[68:100]);
        burnToken = address(uint160(uint256(bytes32(data[100:132]))));
        destinationCaller = bytes32(data[132:164]);
        maxFee = uint256(bytes32(data[164:196]));
        minFinalityThreshold = uint32(uint256(bytes32(data[196:228])));
        // hookData head pointer sits at data[228:260]; payload follows. We don't decode it
        // here because the policy treats it as opaque.
    }

    /// @notice Parses `approve(address spender, uint256 amount)`.
    function decodeApprove(bytes calldata data)
        internal
        pure
        returns (address spender, uint256 amount)
    {
        if (data.length != 4 + 64) revert MalformedCall();
        spender = address(uint160(uint256(bytes32(data[4:36]))));
        amount = uint256(bytes32(data[36:68]));
    }
}
