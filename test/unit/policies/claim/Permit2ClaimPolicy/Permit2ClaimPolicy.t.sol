// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Testing
import { Base_Test } from "@test/Base.t.sol";

// Contracts
import { Permit2ClaimPolicy } from "@policies/claim/permit2/Permit2ClaimPolicy.sol";

// Mocks
import { MockSubPolicy } from "@mocks/MockSubPolicy.sol";

// Libraries
import { BaseConfigLib } from "@policies/claim/base/lib/BaseConfigLib.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import {
    PolicyConfig,
    MODE_SKIP,
    MODE_CHECK_STORAGE,
    MODE_CHECK_CATCHALL,
    MODE_CHECK_SUBPOLICY,
    FIELD_TOKEN_IN
} from "@policies/claim/base/types/BaseDataTypes.sol";

/// @title Permit2ClaimPolicy Unit Test Base
/// @notice Base contract for Permit2ClaimPolicy and lib unit tests
contract Permit2ClaimPolicy_Unit_Test is Base_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using BaseConfigLib for uint32;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    Permit2ClaimPolicy internal permit2ClaimPolicy;
    MockSubPolicy internal mockSubPolicy;
    ConfigId internal configId;
    address internal account;

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    address internal constant PERMIT2_ADDRESS = 0x000000000022D473030F116dDEE9F6B43aC78BA3;

    uint256 internal constant CHAIN_ID_1 = 1;
    uint256 internal constant CHAIN_ID_2 = 42_161;

    address internal token1;
    address internal token2;
    address internal token3;

    bytes32 internal constant HASH = keccak256("test");

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        super.setUp();
        permit2ClaimPolicy = new Permit2ClaimPolicy(PERMIT2_ADDRESS);
        mockSubPolicy = new MockSubPolicy();
        configId = ConfigId.wrap(bytes32(uint256(1)));
        account = makeAddr("account");
        token1 = makeAddr("token1");
        token2 = makeAddr("token2");
        token3 = makeAddr("token3");
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Builds a PolicyConfig with specified field mode
    function _buildConfig(uint8 fieldId, uint8 mode) internal pure returns (PolicyConfig) {
        uint32 modeConfig = uint32(0).setFieldMode(fieldId, mode);
        return PolicyConfig.wrap(modeConfig);
    }

    /// @notice Packs token address into bytes32 for Permit2
    /// @dev Left-padded address: bytes32(bytes20(token))
    function _packToken(address token) internal pure returns (bytes32) {
        return bytes32(bytes20(token));
    }

    /// @notice Encodes tokenIn config for Permit2 initialization
    /// @dev Layout: [count (1)] + [chainId (32) + token (20)] per entry
    function _encodeTokenInConfig(
        uint256[] memory chainIds,
        address[] memory tokens
    )
        internal
        pure
        returns (bytes memory)
    {
        require(chainIds.length == tokens.length, "Length mismatch");
        bytes memory encoded = abi.encodePacked(uint8(chainIds.length));
        for (uint256 i = 0; i < chainIds.length; i++) {
            encoded = abi.encodePacked(encoded, chainIds[i], tokens[i]);
        }
        return encoded;
    }

    /// @notice Encodes tokenIn array for validation (length + TokenPermissions[])
    /// @dev TokenPermissions = [token (32 bytes left-padded), amount (32 bytes)]
    function _encodeTokenInArray(
        address[] memory tokens,
        uint256[] memory amounts
    )
        internal
        pure
        returns (bytes memory)
    {
        require(tokens.length == amounts.length, "Length mismatch");
        bytes memory encoded = abi.encodePacked(uint8(tokens.length));
        for (uint256 i = 0; i < tokens.length; i++) {
            // Token is left-padded to 32 bytes
            encoded = abi.encodePacked(encoded, bytes32(uint256(uint160(tokens[i]))), amounts[i]);
        }
        return encoded;
    }

    /// @notice Encodes a pre-computed hash for SKIP mode
    function _encodeTokenInHash(bytes32 hash) internal pure returns (bytes memory) {
        return abi.encodePacked(hash);
    }
}
