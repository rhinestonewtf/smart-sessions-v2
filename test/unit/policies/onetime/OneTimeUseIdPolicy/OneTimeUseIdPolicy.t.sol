// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

// Dependencies
import { Test } from "@forge-std/Test.sol";

// Contracts
import { OneTimeUseIdPolicy } from "@policies/onetime/OneTimeUseIdPolicy.sol";

// Interfaces
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import { VALIDATION_SUCCESS, VALIDATION_FAILED } from "erc7579/interfaces/IERC7579Module.sol";

/// @notice Stands in for the IntentExecutor's Permit2 nonce ledger: a nonce counts as consumed
///         (its pre-claim ran) unless a test marks it otherwise.
contract MockPermit2NonceExecutor {
    mapping(uint256 nonce => bool) public unconsumed;

    function setUnconsumed(uint256 nonce) external {
        unconsumed[nonce] = true;
    }

    function isPermit2IntentNonceConsumed(uint256 nonce, address) external view returns (bool) {
        return !unconsumed[nonce];
    }
}

/// @title OneTimeUseIdPolicy Unit Test Base
/// @notice Base contract for OneTimeUseIdPolicy unit tests. Every session in this fixture is
///         installed on every action it permits, so `cfgA`/`cfgB` stand in for two action slots
///         of the SAME session sharing one spend, while `ID_A`/`ID_B` stand in for two DIFFERENT
///         sessions on the same account.
abstract contract OneTimeUseIdPolicy_Unit_Test is Test {
    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    uint256 internal constant SUCCESS = VALIDATION_SUCCESS;
    uint256 internal constant FAILED = VALIDATION_FAILED;

    /// @dev The real Permit2 deployment address. The policy tells the settling ERC-1271 check
    ///      apart from the pre-claim one purely by whether the caller is this address.
    address internal constant PERMIT2 = 0x000000000022D473030F116dDEE9F6B43aC78BA3;

    ConfigId internal cfgA = ConfigId.wrap(keccak256("session.A"));
    ConfigId internal cfgB = ConfigId.wrap(keccak256("session.B"));

    uint256 internal constant ID_A = 0xBEEF;
    uint256 internal constant ID_B = 0xCAFE;

    /// @dev The deadline value meaning "never expires"
    uint256 internal constant NO_DEADLINE = 0;

    /// @dev Stands in for a settlement's own Permit2 nonce, used purely as a witness
    uint256 internal constant WITNESS_1 = 1337;
    uint256 internal constant WITNESS_2 = 4242;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    OneTimeUseIdPolicy internal policy;

    address internal multiplexer;
    address internal account;

    /// @dev Stands in for the executor's pre-claim ERC-1271 call, which arrives before the burn
    address internal executor;

    /// @dev The id pinned under each config, so a settlement batch can lead with its own burn
    mapping(ConfigId => uint256) internal pinnedId;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public virtual {
        multiplexer = makeAddr("multiplexer");
        account = makeAddr("account");
        executor = address(new MockPermit2NonceExecutor());

        policy = new OneTimeUseIdPolicy(ISignatureTransfer(PERMIT2), executor);

        _install(cfgA, ID_A);
        _install(cfgB, ID_B);
    }

    /*//////////////////////////////////////////////////////////////
                               HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Pins `id` under `cfg` for `account`, with no deadline, as the multiplexer
    function _install(ConfigId cfg, uint256 id) internal {
        _install(cfg, id, NO_DEADLINE);
    }

    /// @notice Pins `id` and `deadline` under `cfg` for `account`, as the multiplexer
    function _install(ConfigId cfg, uint256 id, uint256 deadline) internal {
        vm.prank(multiplexer);
        policy.initializeWithMultiplexer(
            account, cfg, abi.encodePacked(bytes32(id), bytes32(deadline))
        );
        pinnedId[cfg] = id;
    }

    /// @notice What the action surface does for one execution in a settlement batch
    function _checkAction(
        ConfigId cfg,
        address target,
        bytes memory data
    )
        internal
        returns (uint256)
    {
        vm.prank(multiplexer);
        return policy.checkAction(cfg, account, target, 0, data);
    }

    /// @notice A settlement batch against `cfg`: its own burn, then a plain execution. Returns the
    ///         plain execution's result.
    function _validate(ConfigId cfg) internal returns (uint256) {
        _validateBurn(cfg);
        return _validatePlain(cfg);
    }

    /// @notice The action surface's check of the session's own burn, which leads every batch
    function _validateBurn(ConfigId cfg) internal returns (uint256) {
        return _checkAction(cfg, address(policy), abi.encodeCall(policy.consume, (pinnedId[cfg])));
    }

    /// @notice A plain, self-call-free execution against `cfg`, with no burn validated before it
    function _validatePlain(ConfigId cfg) internal returns (uint256) {
        return _checkAction(cfg, address(0), "");
    }

    /// @notice The account burns `id`, nominating no settlement
    function _consume(uint256 id) internal {
        vm.prank(account);
        policy.consume(id);
    }

    /// @notice The account burns `id`, nominating the settlement identified by `witness`
    function _consumeFor(uint256 id, uint256 witness) internal {
        vm.prank(account);
        policy.consumeFor(id, witness);
    }

    /// @notice A claim blob shaped like `Permit2ClaimPolicy`'s: arbiter(20) . nonce(32) .
    /// mandate(32)
    function _blob(uint256 nonce) internal pure returns (bytes memory) {
        return abi.encodePacked(address(0xA4B17E4), bytes32(nonce), bytes32(uint256(99)));
    }

    /// @notice The pre-claim ERC-1271 check, which runs before the burn
    function _preClaimCheck(ConfigId cfg, uint256 nonce) internal returns (bool) {
        vm.prank(multiplexer);
        return policy.check1271SignedAction(cfg, executor, account, bytes32(0), _blob(nonce));
    }

    /// @notice The settling ERC-1271 check, which moves the money
    function _settlingCheck(ConfigId cfg, uint256 nonce) internal returns (bool) {
        vm.prank(multiplexer);
        return policy.check1271SignedAction(cfg, PERMIT2, account, bytes32(0), _blob(nonce));
    }
}
