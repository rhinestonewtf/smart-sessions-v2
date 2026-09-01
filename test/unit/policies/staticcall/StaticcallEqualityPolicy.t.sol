// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.27;

// Testing
import { Test } from "@forge-std/Test.sol";

// Contracts
import { StaticcallEqualityPolicy } from "@policies/staticcall/StaticcallEqualityPolicy.sol";

// Interfaces
import { IPolicy, IActionPolicy } from "@smartsessions/interfaces/IPolicy.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import { VALIDATION_SUCCESS, VALIDATION_FAILED } from "erc7579/interfaces/IERC7579Module.sol";

/// @notice Harness exposing the base's internal mechanics
/// @dev `_readExpected` is satisfied with a settable value so the word-comparison logic can be
///      exercised on its own, independently of any particular resolution strategy.
contract StaticcallEqualityPolicyHarness is StaticcallEqualityPolicy {
    bytes32 internal expectedValue;
    bool internal resolvable = true;

    function setExpected(bytes32 value) external {
        expectedValue = value;
    }

    function setResolvable(bool value) external {
        resolvable = value;
    }

    function _readExpected() internal view override returns (bytes32, bool) {
        return (expectedValue, resolvable);
    }

    /// @notice External wrapper over the internal comparison helper
    function wordEquals(
        bytes calldata data,
        uint256 offset,
        bytes32 expected
    )
        external
        pure
        returns (bool)
    {
        return _wordEquals(data, offset, expected);
    }

    /// @notice Exposes `_readExpected` for the fail-closed contract tests
    function readExpected() external view returns (bytes32, bool) {
        return _readExpected();
    }

    /// @notice Pins the first argument word, so the fail-closed contract can be observed
    function checkAction(
        ConfigId,
        address,
        address,
        uint256,
        bytes calldata data
    )
        external
        view
        override
        returns (uint256)
    {
        (bytes32 value, bool ok) = _readExpected();
        if (!ok) return VALIDATION_FAILED;
        return _wordEquals(data, 0, value) ? VALIDATION_SUCCESS : VALIDATION_FAILED;
    }
}

/// @notice A subclass that forgets to override `checkAction`, to pin the default
contract ForgetfulPolicy is StaticcallEqualityPolicy {
    function _readExpected() internal pure override returns (bytes32, bool) {
        return (bytes32(uint256(1)), true);
    }
}

/// @title StaticcallEqualityPolicy Unit Tests
/// @notice Tests for the abstract base's shared mechanics
/// @dev End-to-end resolution behaviour is covered by ZeroExSettlerPolicy's suite; this file
///      isolates the parts every concrete policy inherits.
contract StaticcallEqualityPolicy_Unit_Test is Test {
    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    StaticcallEqualityPolicyHarness internal harness;

    ConfigId internal configId;
    address internal account;
    bytes32 internal expected;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public {
        harness = new StaticcallEqualityPolicyHarness();
        configId = ConfigId.wrap(bytes32(uint256(1)));
        account = makeAddr("account");
        expected = bytes32(uint256(uint160(makeAddr("settler"))));
        harness.setExpected(expected);
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Builds calldata with `words` ABI words after a dummy selector
    function _calldata(bytes32[] memory words) internal pure returns (bytes memory data) {
        data = abi.encodePacked(bytes4(0xdeadbeef));
        for (uint256 i; i < words.length; i++) {
            data = abi.encodePacked(data, words[i]);
        }
    }

    /*//////////////////////////////////////////////////////////////
                              WORD EQUALS
    //////////////////////////////////////////////////////////////*/

    function test_WordEquals_MatchesAtEachOffset() public view {
        bytes32[] memory words = new bytes32[](3);
        words[0] = expected;
        words[1] = bytes32(uint256(7));
        words[2] = expected;

        bytes memory data = _calldata(words);

        assertTrue(harness.wordEquals(data, 0, expected), "offset 0");
        assertFalse(harness.wordEquals(data, 32, expected), "offset 32 differs");
        assertTrue(harness.wordEquals(data, 64, expected), "offset 64");
    }

    /// @dev Offsets skip the selector; reading from the raw calldata start would be off by four
    function test_WordEquals_OffsetsAreRelativeToArguments() public view {
        bytes32[] memory words = new bytes32[](1);
        words[0] = expected;

        // A misaligned read of the same buffer must not match
        assertTrue(harness.wordEquals(_calldata(words), 0, expected), "aligned");
        assertFalse(harness.wordEquals(_calldata(words), 1, expected), "shifted by one byte");
    }

    /*//////////////////////////////////////////////////////////////
                          BOUNDS AND MALFORMED
    //////////////////////////////////////////////////////////////*/

    function test_WordEquals_FailsWhenCalldataHasNoSelector() public view {
        assertFalse(harness.wordEquals(hex"001122", 0, expected), "3 bytes");
        assertFalse(harness.wordEquals("", 0, expected), "empty");
    }

    function test_WordEquals_FailsWhenArgumentsAreShorterThanAWord() public view {
        assertFalse(
            harness.wordEquals(abi.encodePacked(bytes4(0xdeadbeef)), 0, expected), "no args"
        );
        assertFalse(
            harness.wordEquals(abi.encodePacked(bytes4(0xdeadbeef), bytes31(0)), 0, expected),
            "31 bytes of args"
        );
    }

    /// @dev An absent pinned word is a mismatch, never a skip
    function test_WordEquals_FailsWhenOffsetIsBeyondCalldata() public view {
        bytes32[] memory words = new bytes32[](1);
        words[0] = expected;
        bytes memory data = _calldata(words);

        assertTrue(harness.wordEquals(data, 0, expected), "present");
        assertFalse(harness.wordEquals(data, 32, expected), "one word past the end");
        assertFalse(harness.wordEquals(data, 96, expected), "far past the end");
    }

    /// @dev A huge offset must return false rather than reverting on overflow
    function test_WordEquals_FailsOnExtremeOffsetWithoutReverting() public view {
        bytes32[] memory words = new bytes32[](1);
        words[0] = expected;
        bytes memory data = _calldata(words);

        assertFalse(harness.wordEquals(data, type(uint256).max, expected), "max offset");
        assertFalse(harness.wordEquals(data, type(uint256).max - 31, expected), "near-max offset");
    }

    function testFuzz_WordEquals_NeverRevertsAndOnlyMatchesTheExactWord(
        uint256 offset,
        bytes32 candidate
    )
        public
        view
    {
        bytes32[] memory words = new bytes32[](2);
        words[0] = candidate;
        words[1] = candidate;
        bytes memory data = _calldata(words);

        bool result = harness.wordEquals(data, offset, expected);

        bool inBounds = offset <= 32;
        assertEq(result, inBounds && candidate == expected, "matches only in bounds and equal");
    }

    /*//////////////////////////////////////////////////////////////
                          RAW COMPARISON
    //////////////////////////////////////////////////////////////*/

    /// @dev Unmasked: dirty upper bytes are a false reject, never a false accept
    function test_WordEquals_DoesNotMaskUpperBytes() public view {
        bytes32 dirty = bytes32(uint256(expected) | (uint256(1) << 250));

        bytes32[] memory words = new bytes32[](1);
        words[0] = dirty;

        assertFalse(harness.wordEquals(_calldata(words), 0, expected), "dirty must not match");
    }

    /*//////////////////////////////////////////////////////////////
                         FAIL-CLOSED CONTRACT
    //////////////////////////////////////////////////////////////*/

    /// @dev `ok == false` must deny even when the word happens to match the calldata. This is the
    ///      contract an override has to honour: signalling failure through `ok`, not by returning
    ///      a zero word, since a zero word would be matched by zeroed calldata.
    function test_CheckAction_DeniesWhenExpectedIsUnresolvable() public {
        bytes memory matching = abi.encodePacked(bytes4(0xdeadbeef), expected);

        assertEq(
            harness.checkAction(configId, account, address(0xA11), 0, matching),
            VALIDATION_SUCCESS,
            "resolvable and matching"
        );

        harness.setResolvable(false);

        (bytes32 value, bool ok) = harness.readExpected();
        assertFalse(ok, "must report failure");
        assertEq(value, expected, "the stale word is still returned, so ok is what matters");

        assertEq(
            harness.checkAction(configId, account, address(0xA11), 0, matching),
            VALIDATION_FAILED,
            "unresolvable must deny despite a matching word"
        );
    }

    /// @dev The specific hazard: zeroed calldata against a zero expected word
    function test_CheckAction_DeniesZeroedCalldataWhenUnresolvable() public {
        harness.setExpected(bytes32(0));
        harness.setResolvable(false);

        bytes memory zeroed = abi.encodePacked(bytes4(0xdeadbeef), bytes32(0));

        assertEq(
            harness.checkAction(configId, account, address(0xA11), 0, zeroed),
            VALIDATION_FAILED,
            "zero must not match zero when unresolvable"
        );
    }

    /*//////////////////////////////////////////////////////////////
                              DEFAULTS
    //////////////////////////////////////////////////////////////*/

    /// @dev A subclass that forgets to override `checkAction` must deny, not allow
    function test_CheckAction_DefaultsToDenied() public {
        ForgetfulPolicy forgetful = new ForgetfulPolicy();

        uint256 result = forgetful.checkAction(
            configId, account, address(0xA11), 0, abi.encodePacked(bytes4(0xdeadbeef), expected)
        );

        assertEq(result, VALIDATION_FAILED, "default must deny");
    }

    function test_SupportsInterface_IsInheritedByEverySubclass() public {
        ForgetfulPolicy forgetful = new ForgetfulPolicy();
        assertTrue(forgetful.supportsInterface(type(IActionPolicy).interfaceId), "IActionPolicy");
    }

    function test_Initialize_IsNoOpAndRepeatable() public {
        vm.expectEmit(true, true, true, true, address(harness));
        emit IPolicy.PolicySet(configId, address(this), account);
        harness.initializeWithMultiplexer(account, configId, "");

        harness.initializeWithMultiplexer(account, configId, hex"deadbeef");
    }

    /// @dev The base contributes no storage, so a subclass starts from a clean layout
    function test_BaseContributesNoStorage() public view {
        // The harness declares two of its own variables; anything beyond them must be untouched
        for (uint256 i = 2; i < 8; i++) {
            assertEq(vm.load(address(harness), bytes32(i)), bytes32(0), "unexpected storage");
        }
    }
}
