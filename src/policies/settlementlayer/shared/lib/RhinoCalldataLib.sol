// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

/// @title RhinoCalldataLib
/// @notice Selectors and inline parsers for the Rhino.fi (DVFDepositContract) calls the
///         orchestrator emits inside an IntentExecutor `Operation.ops` (see
///         `planning/strategies/rhino/element.ts` in `rhinestonewtf/orchestrator`).
library RhinoCalldataLib {
    error MalformedCall();

    /// @dev `IERC20.approve(address,uint256)`.
    bytes4 internal constant SEL_ERC20_APPROVE = 0x095ea7b3;

    /// @dev `DVFDepositContract.depositWithId(address token, uint256 amount, uint256 commitmentId)`.
    bytes4 internal constant SEL_DEPOSIT_WITH_ID = 0x2700bbaf;

    function decodeApprove(bytes calldata data)
        internal
        pure
        returns (address spender, uint256 amount)
    {
        if (data.length != 4 + 64) revert MalformedCall();
        spender = address(uint160(uint256(bytes32(data[4:36]))));
        amount = uint256(bytes32(data[36:68]));
    }

    function decodeDepositWithId(bytes calldata data)
        internal
        pure
        returns (address token, uint256 amount, uint256 commitmentId)
    {
        if (data.length != 4 + 96) revert MalformedCall();
        token = address(uint160(uint256(bytes32(data[4:36]))));
        amount = uint256(bytes32(data[36:68]));
        commitmentId = uint256(bytes32(data[68:100]));
    }
}
