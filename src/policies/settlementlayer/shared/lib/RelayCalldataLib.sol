// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

/// @title RelayCalldataLib
/// @notice Selectors and inline parsers for the Relay-shaped calls the orchestrator emits
///         inside an IntentExecutor signed `Operation.ops`.
/// @dev Selectors taken from `relay.ts` / `intentExecutor.ts` in `rhinestonewtf/orchestrator`
///      (see `compact/adapters/implementations/relay.ts` and the Relay ABI in
///      `contracts/abi/rhinestone/adapters/relay.ts`).
library RelayCalldataLib {
    error MalformedCall();

    /// @dev `IERC20.approve(address,uint256)`.
    bytes4 internal constant SEL_ERC20_APPROVE = 0x095ea7b3;
    /// @dev `IERC20.transfer(address,uint256)`.
    bytes4 internal constant SEL_ERC20_TRANSFER = 0xa9059cbb;

    /// @dev Relay `ERC20Router.multicall(Call3Value[] calls, address refundTo, address
    /// nftRecipient, bytes metadata)`.
    bytes4 internal constant SEL_RELAY_MULTICALL = 0xcd6e13f7;
    /// @dev Relay `ERC20Router.transferAndMulticall(address[] tokens, uint256[] amounts,
    /// Call3Value[] calls, address sender, address recipient)`.
    bytes4 internal constant SEL_RELAY_TRANSFER_AND_MULTICALL = 0x30875056;

    // Note on IntentExecutorAdapter selectors: the orchestrator emits one of
    //   handleFill_intentExecutor_handlePermit2TargetOps(...)
    //   handleFill_intentExecutor_executeSinglechainOps(bytes)
    //   handleFill_intentExecutor_executeSinglechainOps_gasRefund((SingleChainOps,GasRefund))
    // The Relay policy matches the adapter by *target address* only — its selector list is
    // versioned with the deployed contract and would churn on every adapter upgrade.

    /// @notice Parses `approve(address spender, uint256 amount)`.
    /// @dev Reverts if calldata isn't the 36-byte payload + 4-byte selector standard form.
    function decodeApprove(bytes calldata data)
        internal
        pure
        returns (address spender, uint256 amount)
    {
        if (data.length != 4 + 64) revert MalformedCall();
        spender = address(uint160(uint256(bytes32(data[4:36]))));
        amount = uint256(bytes32(data[36:68]));
    }

    /// @notice Parses `transfer(address to, uint256 amount)`.
    function decodeTransfer(bytes calldata data)
        internal
        pure
        returns (address to, uint256 amount)
    {
        if (data.length != 4 + 64) revert MalformedCall();
        to = address(uint160(uint256(bytes32(data[4:36]))));
        amount = uint256(bytes32(data[36:68]));
    }
}
