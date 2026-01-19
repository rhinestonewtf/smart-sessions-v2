// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

contract AddressBook {
    address immutable INTENT_EXECUTOR;

    constructor(address intentExecutor) {
        INTENT_EXECUTOR = intentExecutor;
    }

    function getAddress(bytes32) external view returns (address) {
        return INTENT_EXECUTOR;
    }
}
