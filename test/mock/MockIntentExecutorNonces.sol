// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

/// @dev The executor's three nonce namespaces, as the mock indexes them
uint8 constant FAMILY_STANDALONE = 0;
uint8 constant FAMILY_PERMIT2 = 1;
uint8 constant FAMILY_COMPACT = 2;

/// @title Mock Intent Executor Nonces
/// @notice Minimal stand-in for the executor's in-flight and consumed-nonce views
contract MockIntentExecutorNonces {
    bool internal $active;
    address internal $inFlightAccount;
    uint256 internal $inFlight;
    mapping(uint8 family => mapping(uint256 nonce => mapping(address account => bool))) internal
        $consumed;
    mapping(uint256 nonce => mapping(address account => bool)) internal $settledElsewhere;

    /// @notice Simulates a settlement being validated, or none when `active` is false
    function setInFlight(bool active, address account, uint256 nonce) external {
        $active = active;
        $inFlightAccount = account;
        $inFlight = nonce;
    }

    /// @notice Simulates one family having consumed this nonce
    function setConsumed(uint8 family, uint256 nonce, address account, bool consumed) external {
        $consumed[family][nonce][account] = consumed;
    }

    /// @notice Simulates the executor reporting another family as having settled this nonce
    /// @dev Independent of `setConsumed`, mirroring the executor: this view excludes whichever
    ///      family is mid-validation, so it is not derivable from the per-family views
    function setSettledElsewhere(uint256 nonce, address account, bool settled) external {
        $settledElsewhere[nonce][account] = settled;
    }

    function currentIntentNonce()
        external
        view
        returns (bool active, address account, uint256 nonce)
    {
        return ($active, $inFlightAccount, $inFlight);
    }

    function isIntentNonceSettledElsewhere(
        uint256 nonce,
        address account
    )
        external
        view
        returns (bool settled)
    {
        return $settledElsewhere[nonce][account];
    }

    function isStandaloneIntentNonceConsumed(
        uint256 nonce,
        address account
    )
        external
        view
        returns (bool used)
    {
        return $consumed[FAMILY_STANDALONE][nonce][account];
    }

    function isPermit2IntentNonceConsumed(
        uint256 nonce,
        address account
    )
        external
        view
        returns (bool used)
    {
        return $consumed[FAMILY_PERMIT2][nonce][account];
    }

    function isCompactIntentNonceConsumed(
        uint256 nonce,
        address account
    )
        external
        view
        returns (bool used)
    {
        return $consumed[FAMILY_COMPACT][nonce][account];
    }
}
