// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Interfaces
import { ISessionValidator } from "@smartsessions/interfaces/ISessionValidator.sol";

// Types
import { ERC7579_MODULE_TYPE_STATELESS_VALIDATOR } from "@smartsessions/DataTypes.sol";

contract NoSessionValidator is ISessionValidator {
    function isModuleType(uint256 id) external pure returns (bool) {
        return id == ERC7579_MODULE_TYPE_STATELESS_VALIDATOR;
    }

    function isInitialized(address, address, bytes32) external pure returns (bool) {
        return true;
    }

    function isInitialized(address) external pure returns (bool) {
        return true;
    }

    function isInitialized(address, address) external pure returns (bool) {
        return true;
    }

    function validateSignatureWithData(
        bytes32,
        bytes calldata,
        bytes calldata
    )
        external
        pure
        override
        returns (bool validSig)
    {
        return false;
    }

    function onInstall(bytes calldata data) external { }

    function onUninstall(bytes calldata data) external { }
}
