// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Dependencies
import { Base_Test } from "@test/Base.t.sol";

// Contracts
import { SignatureLib } from "@lib/SignatureLib.sol";
import { MockERC1271 } from "@mocks/MockERC1271.sol";

contract SignatureLib_Unit_Test is Base_Test {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using SignatureLib for *;

    /*//////////////////////////////////////////////////////////////
                                VARIABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice EOA accounts
    address internal allocatorEOA;
    address internal userEOA;
    address internal attacker;

    /// @notice Smart account wallets
    address internal allocatorWallet;
    address internal userWallet;

    /// @notice Test private keys
    uint256 internal allocatorPrivateKey;
    uint256 internal userPrivateKey;
    uint256 internal attackerPrivateKey;

    /// @notice Test hashes
    bytes32 internal testHash;
    bytes32 internal invalidHash;

    /*//////////////////////////////////////////////////////////////
                                  SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        // Call the base setup function
        super.setUp();

        // Setup test accounts with known private keys
        allocatorPrivateKey = 0xA11CE;
        userPrivateKey = 0xB0B;
        attackerPrivateKey = 0xBAD;

        // Create EOA addresses
        allocatorEOA = vm.addr(allocatorPrivateKey);
        userEOA = vm.addr(userPrivateKey);
        attacker = vm.addr(attackerPrivateKey);

        // Deploy smart account wallets
        allocatorWallet = deployMockWallet(allocatorEOA);
        userWallet = deployMockWallet(userEOA);

        // Setup test hashes
        testHash = keccak256("test message");
        invalidHash = keccak256("invalid message");

        // Label addresses for better trace output
        vm.label(allocatorEOA, "AllocatorEOA");
        vm.label(userEOA, "UserEOA");
        vm.label(attacker, "Attacker");
        vm.label(allocatorWallet, "AllocatorWallet");
        vm.label(userWallet, "UserWallet");
    }

    /*//////////////////////////////////////////////////////////////
                             SIGNATURE HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Creates a valid ECDSA signature for a given hash and private key
    function createEOASignature(
        bytes32 hash,
        uint256 privateKey
    )
        internal
        pure
        returns (bytes memory)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, hash);
        return abi.encodePacked(r, s, v);
    }

    /// @notice Creates a signature for a smart account (owner signs with their EOA)
    function createSmartAccountSignature(
        bytes32 hash,
        uint256 ownerPrivateKey
    )
        internal
        pure
        returns (bytes memory)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, hash);
        return abi.encodePacked(r, s, v);
    }

    /// @notice Creates an invalid signature
    function createInvalidSignature() internal pure returns (bytes memory) {
        return abi.encodePacked(bytes32(0), bytes32(0), uint8(27));
    }

    /// @notice Creates a malformed signature (wrong length)
    function createMalformedSignature() internal pure returns (bytes memory) {
        return abi.encodePacked(bytes32(0));
    }

    /*//////////////////////////////////////////////////////////////
                               MOCK HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Deploy a mock ERC1271 wallet for a user
    function deployMockWallet(address owner) internal returns (address) {
        MockERC1271 wallet = new MockERC1271(owner);
        return address(wallet);
    }

    /// @notice Deploy a failing mock wallet
    function deployFailingWallet() internal returns (address) {
        MockERC1271 wallet = new MockERC1271(address(0));
        wallet.setShouldReturnValid(false);
        return address(wallet);
    }
}
