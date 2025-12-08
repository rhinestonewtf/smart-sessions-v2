// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Interfaces
import { I1271Policy } from "@smartsessions/interfaces/IPolicy.sol";
import { IERC165 } from "@openzeppelin/contracts/interfaces/IERC165.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";

/// @title MockSubPolicy
/// @notice Mock sub-policy for testing initialization and validation
contract MockSubPolicy {
    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Return value for check1271SignedAction
    bool public returnValue;

    /// @notice Count of initializeWithMultiplexer calls
    uint256 public initializeWithMultiplexerCallCount;

    /// @notice Last configId passed to initializeWithMultiplexer
    ConfigId public lastConfigId;

    /// @notice Last account passed to initializeWithMultiplexer
    address public lastAccount;

    /// @notice Last init data passed to initializeWithMultiplexer
    bytes public lastInitData;

    /*//////////////////////////////////////////////////////////////
                            CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Sets the return value for check1271SignedAction
    function setReturnValue(bool _returnValue) external {
        returnValue = _returnValue;
    }

    /*//////////////////////////////////////////////////////////////
                            EXTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Mock initializeWithMultiplexer implementation
    function initializeWithMultiplexer(
        address _account,
        ConfigId _configId,
        bytes calldata _initData
    )
        external
    {
        initializeWithMultiplexerCallCount++;
        lastConfigId = _configId;
        lastAccount = _account;
        lastInitData = _initData;
    }

    /// @notice Mock check1271SignedAction implementation (I1271Policy interface)
    function check1271SignedAction(
        ConfigId,
        address,
        address,
        bytes32,
        bytes calldata
    )
        external
        view
        returns (bool)
    {
        return returnValue;
    }

    /// @notice ERC165 supportsInterface implementation
    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return
            interfaceId == type(IERC165).interfaceId || interfaceId == type(I1271Policy).interfaceId;
    }
}
