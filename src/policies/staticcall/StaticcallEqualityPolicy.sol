// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.28;

// Interfaces
import { IPolicy, IActionPolicy } from "@smartsessions/interfaces/IPolicy.sol";
import { IERC165 } from "@openzeppelin/contracts/interfaces/IERC165.sol";

// Types
import { ConfigId } from "@smartsessions/DataTypes.sol";
import { VALIDATION_FAILED } from "erc7579/interfaces/IERC7579Module.sol";

/// @title Staticcall Equality Policy
/// @author Rhinestone
/// @notice Abstract action policy comparing words of the authorised calldata against a value
///         resolved by a staticcall at validation time
/// @dev The candidate value comes from the calldata being authorised and the expected value comes
///      from `_readExpected`, so the assertion tracks whatever the callee answers right now. That
///      is what lets a session survive the answer changing, with no re-install.
///
///      This base holds NO configuration: no constructor, no immutables, no storage. A concrete
///      policy hardcodes what it resolves and which words it pins, so the assertion is a property
///      of the source code rather than of how someone deployed it. There is nothing to configure
///      and therefore nothing to misconfigure.
///
/// @dev `_readExpected` is the intended override point. An override MUST preserve the fail-closed
///      contract and return `ok = false` on any failure rather than a zero word: an `expected` of
///      zero compared against zeroed calldata would pass, which is exactly the hole the length
///      check exists to close.
///
/// @dev ERC-4337 CAVEAT: resolving the expected value makes an external call, reading storage of a
///      contract that is neither the sender nor associated with it. That breaks the ERC-7562
///      validation rules, so a public bundler will reject a user operation whose validation
///      reaches this policy unless the callee is staked. It is intended for the intent / ERC-1271
///      settlement path. Do not install it behind a code path that runs during ERC-4337 validation
///      against a public mempool.
abstract contract StaticcallEqualityPolicy is IActionPolicy {
    /// @dev Length of the selector preceding the ABI-encoded arguments
    uint256 internal constant SELECTOR_LENGTH = 4;

    /// @dev Size of the word that is read and compared
    uint256 internal constant WORD_SIZE = 32;

    /// @inheritdoc IPolicy
    /// @notice No-op initialization; the policy holds no per-session configuration
    /// @dev `initData` is ignored rather than required to be empty, so installing a session cannot
    ///      revert over a value that cannot affect this policy's decision.
    /// @param account The account being configured
    /// @param configId The configuration ID
    function initializeWithMultiplexer(
        address account,
        ConfigId configId,
        bytes calldata /* initData */
    )
        external
        virtual
    {
        emit IPolicy.PolicySet(configId, msg.sender, account);
    }

    /// @notice Resolves the value the pinned calldata words must equal
    /// @dev Unimplemented: a concrete policy hardcodes the call it resolves. An override MUST
    ///      return `ok = false` on a revert, a codeless callee, or an unexpected returndata
    ///      length. Returning `(bytes32(0), true)` on failure would let zeroed calldata pass.
    /// @return expected The expected word
    /// @return ok False if the value could not be resolved, which must deny the action
    function _readExpected() internal view virtual returns (bytes32 expected, bool ok);

    /// @notice Checks whether the word at `offset` in `data` equals `expected`
    /// @dev Offsets are relative to the start of the ABI-encoded arguments, so they skip the
    ///      4-byte selector; argument N of an all-static head sits at `N * 32`. An absent word is
    ///      a mismatch, never a skip.
    ///
    ///      The comparison is raw and unmasked. Both sides are ABI words, so a clean encoding
    ///      always matches, and dirty upper bytes then cause a false reject rather than a false
    ///      accept - masking would invert that.
    /// @param data The full calldata of the action, including its 4-byte selector
    /// @param offset Argument-relative offset of the word to compare
    /// @param expected The value the word must equal
    /// @return True if the word is present and equal
    function _wordEquals(
        bytes calldata data,
        uint256 offset,
        bytes32 expected
    )
        internal
        pure
        virtual
        returns (bool)
    {
        if (data.length < SELECTOR_LENGTH) return false;
        bytes calldata args = data[SELECTOR_LENGTH:];

        // Written as a subtraction so a large offset cannot overflow the bound
        if (args.length < WORD_SIZE || offset > args.length - WORD_SIZE) return false;

        bytes32 word;
        assembly ("memory-safe") {
            word := calldataload(add(args.offset, offset))
        }

        return word == expected;
    }

    /// @inheritdoc IActionPolicy
    /// @notice Denies by default; a concrete policy overrides this with its own pinned words
    /// @dev Defaulting to VALIDATION_FAILED means a subclass that forgets to override denies
    ///      everything rather than allowing everything.
    /// @return VALIDATION_FAILED
    function checkAction(
        ConfigId, /* id */
        address, /* account */
        address, /* target */
        uint256, /* value */
        bytes calldata /* data */
    )
        external
        view
        virtual
        override
        returns (uint256)
    {
        return VALIDATION_FAILED;
    }

    /// @notice Checks if this contract implements the given interface
    /// @dev IActionPolicy support is mandatory: ConfigLib.requirePolicyType refuses to install an
    ///      action policy that does not advertise it.
    /// @param interfaceID The interface identifier to check
    /// @return True if the interface is supported
    function supportsInterface(bytes4 interfaceID) external pure virtual returns (bool) {
        return interfaceID == type(IERC165).interfaceId || interfaceID == type(IPolicy).interfaceId
            || interfaceID == type(IActionPolicy).interfaceId;
    }
}
