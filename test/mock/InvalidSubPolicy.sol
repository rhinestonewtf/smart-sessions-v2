// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { IERC165 } from "@openzeppelin/contracts/interfaces/IERC165.sol";

/// @notice A contract that implements IERC165 but NOT I1271Policy
contract InvalidSubPolicy is IERC165 {
    function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
        return interfaceId == type(IERC165).interfaceId;
    }
}
