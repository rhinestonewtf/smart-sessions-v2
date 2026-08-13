// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Testing
import { Base_Test } from "@test/Base.t.sol";

// Contracts
import { NoncePinPolicy } from "@policies/claim/permit2/NoncePinPolicy.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";

/// @title NoncePinPolicy Unit Test Base
/// @notice Base contract for NoncePinPolicy unit tests
contract NoncePinPolicy_Unit_Test is Base_Test {
    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    NoncePinPolicy internal noncePinPolicy;
    ConfigId internal configId;
    address internal account;

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @dev The nonce pinned by default in setUp
    uint256 internal constant PINNED_NONCE = 42;

    /// @dev Arbitrary deadline used in test payloads; this policy does not read it
    uint256 internal constant DEADLINE = 1_800_000_000;

    /// @dev Stand-in for the ERC-1271 caller; this policy does not inspect it
    address internal constant REQUEST_SENDER = 0x000000000022D473030F116dDEE9F6B43aC78BA3;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        super.setUp();

        noncePinPolicy = new NoncePinPolicy();
        configId = ConfigId.wrap(keccak256("nonce.pin.config"));
        account = makeAddr("account");
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev Builds a Permit2 claim payload carrying `nonce` at offset [20:52]
    /// @param nonce The nonce to embed
    /// @return payload A well-formed payload prefix: arbiter, nonce, deadline
    function _claimPayload(uint256 nonce) internal pure returns (bytes memory payload) {
        // arbiter (20 bytes) | nonce (32 bytes) | deadline (32 bytes)
        return abi.encodePacked(address(0xA11CE), nonce, DEADLINE);
    }

    /// @dev Pins `nonce` for the default config and account, as `multiplexer`
    function _pin(address multiplexer, uint256 nonce) internal {
        vm.prank(multiplexer);
        noncePinPolicy.initializeWithMultiplexer(account, configId, abi.encode(nonce));
    }
}
