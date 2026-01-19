// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

/// @title MockArbiter
/// @notice Mock arbiter for testing qualification hash computation
contract MockArbiter {
    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Return value for qualificationHash
    bytes32 public qualificationHashReturn;

    /*//////////////////////////////////////////////////////////////
                            CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Sets the return value for qualificationHash
    function setQualificationHash(bytes32 _hash) external {
        qualificationHashReturn = _hash;
    }

    /*//////////////////////////////////////////////////////////////
                            EXTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Mock qualificationHash implementation (IArbiter interface)
    function qualificationHash(bytes calldata) external view returns (bytes32) {
        return qualificationHashReturn;
    }
}
