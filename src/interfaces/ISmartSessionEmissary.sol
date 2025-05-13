// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface ISmartSessionEmissary {
    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown when the sender is not a whitelisted source
    error UnauthorizedSource();

    /*//////////////////////////////////////////////////////////////
                                 VERIFY
    //////////////////////////////////////////////////////////////*/

    function verifyExecution(
        address account,
        bytes32 hash,
        bytes calldata emissaryData,
        bytes calldata executions,
        bytes12 lockTag
    )
        external;
}
